"""Backend for the clinic management system, serverless edition.

A single AWS Lambda function behind one API Gateway POST endpoint. Every
operation the desktop client can perform arrives as a JSON body:

    {"action": "schedule_appointment", "payload": {"doctor_id": "D01", ...}}

and the response is always:

    {"ok": true,  "data": ...}
    {"ok": false, "error": "human readable message"}

This function is the ONLY component that touches DynamoDB or Bedrock. It runs
under an IAM execution role, so no credentials appear anywhere in the code.

Deploy with deploy.py in the same folder.
"""

import hashlib
import json
import os
from datetime import datetime
from decimal import Decimal

import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

REGION = os.environ.get("AWS_REGION", "us-east-1")
BEDROCK_MODEL_ID = os.environ.get(
    "BEDROCK_MODEL_ID", "anthropic.claude-3-haiku-20240307-v1:0"
)

dynamodb = boto3.resource("dynamodb", region_name=REGION)
bedrock = boto3.client("bedrock-runtime", region_name=REGION)

patients_table = dynamodb.Table("patients")
staff_table = dynamodb.Table("staff")
appointments_table = dynamodb.Table("Appointments")
medical_records_table = dynamodb.Table("medicalRecord")
receipts_table = dynamodb.Table("receipts")
availability_table = dynamodb.Table("availability")
observations_table = dynamodb.Table("observations")
medications_table = dynamodb.Table("medications")


class BusinessError(Exception):
    """A refusal the client should show as-is (duplicate ID, blocked date...)."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def clean(value):
    """Convert DynamoDB Decimals back into JSON-friendly numbers."""
    if isinstance(value, Decimal):
        return int(value) if value % 1 == 0 else float(value)
    if isinstance(value, dict):
        return {key: clean(item) for key, item in value.items()}
    if isinstance(value, list):
        return [clean(item) for item in value]
    return value


def respond(status, payload):
    return {
        "statusCode": status,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(payload, default=str),
    }


def require(payload, *fields):
    """Raise unless every named field carries a non-empty value.

    0 and False are valid values, so a plain truthiness test would wrongly
    report amount=0 as a missing field.
    """
    missing = [
        field for field in fields
        if payload.get(field) is None or str(payload.get(field)).strip() == ""
    ]
    if missing:
        raise BusinessError(f"Missing required field(s): {', '.join(missing)}")


def collect(table, operation, base_kwargs):
    """Run query/scan and follow LastEvaluatedKey so nothing is truncated."""
    items = []
    kwargs = dict(base_kwargs)
    while True:
        page = getattr(table, operation)(**kwargs)
        items.extend(page.get("Items", []))
        if "LastEvaluatedKey" not in page:
            return items
        kwargs["ExclusiveStartKey"] = page["LastEvaluatedKey"]


def by_partition_key(table, key, value, index_name=None):
    """Fetch every item whose `key` equals `value`.

    The original project used two different key layouts for the same table in
    different places, so instead of assuming one layout this tries the named
    index first, then the base table, and finally falls back to a filtered
    scan. Whatever works, works.
    """
    attempts = [index_name, None] if index_name else [None]
    for candidate in attempts:
        kwargs = {
            "KeyConditionExpression": Key(key).eq(value),
        }
        if candidate:
            kwargs["IndexName"] = candidate
        try:
            return collect(table, "query", kwargs)
        except ClientError:
            continue
    return collect(
        table,
        "scan",
        {
            "FilterExpression": Key(key).eq(value),
        },
    )


def get_patient(patient_id):
    return patients_table.get_item(Key={"patient_id": patient_id}).get("Item")


def must_get_patient(patient_id):
    patient = get_patient(patient_id)
    if not patient:
        raise BusinessError(f"Patient {patient_id} was not found.")
    return patient


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------
def hash_password(password):
    """SHA-256 hex digest. Deliberately simple: the honest upgrade path is a
    Cognito User Pool (salted, adaptive hashing, MFA), not hand-rolled crypto
    here."""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def op_login(payload):
    """Staff sign-in against the `staff` table (passwords stored as hashes).

    The client holds no accounts at all; this is the single source of truth
    for staff identity until a Cognito authorizer replaces it.
    """
    require(payload, "username", "password", "role")
    username = str(payload["username"]).strip()
    role = str(payload["role"]).strip()
    account = staff_table.get_item(Key={"username": username}).get("Item")
    if not account:
        raise BusinessError("No staff account with that username.")
    if account.get("password_sha256") != hash_password(str(payload["password"])):
        raise BusinessError("Incorrect password.")
    if str(account.get("role")) != role:
        raise BusinessError("This account belongs to a different role.")
    return {"role": role, "display_name": account["username"]}


# ---------------------------------------------------------------------------
# Patients
# ---------------------------------------------------------------------------
def op_list_patients(_payload):
    return collect(patients_table, "scan", {})


def op_get_patient(payload):
    require(payload, "patient_id")
    return get_patient(payload["patient_id"].strip())


def op_create_patient(payload):
    require(
        payload,
        "patient_id", "patient_name", "patient_IC",
        "patient_address", "patient_number", "patient_BOD",
    )
    patient_id = payload["patient_id"].strip()
    item = {
        "patient_id": patient_id,
        "patient_name": payload["patient_name"],
        "patient_IC": payload["patient_IC"],
        "patient_address": payload["patient_address"],
        "patient_number": payload["patient_number"],
        "patient_BOD": payload["patient_BOD"],
    }
    # The duplicate-ID check lives in DynamoDB itself, not in a prior read:
    # two concurrent creates race on the condition, so only one can win.
    try:
        patients_table.put_item(
            Item=item,
            ConditionExpression="attribute_not_exists(patient_id)",
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            raise BusinessError(f"Patient ID {patient_id} already exists.")
        raise
    return {"patient_id": patient_id}


def op_update_patient(payload):
    require(
        payload,
        "patient_id", "patient_name", "patient_IC",
        "patient_address", "patient_number", "patient_BOD",
    )
    patient_id = payload["patient_id"].strip()
    must_get_patient(patient_id)
    patients_table.update_item(
        Key={"patient_id": patient_id},
        UpdateExpression=(
            "SET patient_name = :name, patient_IC = :ic, patient_address = :address, "
            "patient_number = :number, patient_BOD = :bod"
        ),
        ExpressionAttributeValues={
            ":name": payload["patient_name"],
            ":ic": payload["patient_IC"],
            ":address": payload["patient_address"],
            ":number": payload["patient_number"],
            ":bod": payload["patient_BOD"],
        },
    )
    return {"patient_id": patient_id}


def op_update_patient_contact(payload):
    require(payload, "patient_id", "patient_address", "patient_number")
    patient_id = payload["patient_id"].strip()
    must_get_patient(patient_id)
    patients_table.update_item(
        Key={"patient_id": patient_id},
        UpdateExpression="SET patient_address = :address, patient_number = :number",
        ExpressionAttributeValues={
            ":address": payload["patient_address"],
            ":number": payload["patient_number"],
        },
    )
    return {"patient_id": patient_id}


# ---------------------------------------------------------------------------
# Appointments
# ---------------------------------------------------------------------------
def op_appointments_for_doctor(payload):
    require(payload, "doctor_id")
    return by_partition_key(
        appointments_table, "doctor_id", payload["doctor_id"].strip(),
        index_name="doctor_id-index",
    )


def op_appointments_for_patient(payload):
    require(payload, "patient_id")
    return by_partition_key(
        appointments_table, "patient_id", payload["patient_id"].strip(),
        index_name="patient_id-index",
    )


def op_schedule_appointment(payload):
    require(payload, "patient_id", "doctor_id", "date", "time")
    patient = must_get_patient(payload["patient_id"].strip())
    doctor_id = payload["doctor_id"].strip()
    date = payload["date"].strip()
    time = payload["time"].strip()

    same_day = [
        appt
        for appt in by_partition_key(appointments_table, "doctor_id", doctor_id,
                                     index_name="doctor_id-index")
        if appt.get("appointment_date") == date
    ]
    if any(appt.get("appointment_time") == time for appt in same_day):
        raise BusinessError(
            f"{doctor_id} already has an appointment at {time} on {date}."
        )

    blocked = availability_table.get_item(
        Key={"doctor_id": doctor_id, "date": date}
    ).get("Item")
    if blocked and blocked.get("status") == "block":
        raise BusinessError(f"{doctor_id} is not available on {date}.")

    item = {
        # Deterministic record id: one row per patient/date/time. The table's
        # primary key IS this attribute, so the condition below makes the
        # duplicate check atomic instead of check-then-put.
        "record_id": f'{patient["patient_id"]}-{date}-{time}',
        "doctor_id": doctor_id,
        "appointment_date": date,
        "appointment_time": time,
        "patient_id": patient["patient_id"],
        "patient_name": patient.get("patient_name", ""),
    }
    try:
        appointments_table.put_item(
            Item=item,
            ConditionExpression="attribute_not_exists(record_id)",
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            raise BusinessError(
                f'{patient["patient_id"]} already has an appointment at {time} on {date}.'
            )
        raise
    return item


# ---------------------------------------------------------------------------
# Receipts
# ---------------------------------------------------------------------------
def op_list_receipts(_payload):
    return collect(receipts_table, "scan", {})


def op_get_receipt(payload):
    require(payload, "receipt_id")
    return receipts_table.get_item(
        Key={"receipt_id": payload["receipt_id"].strip()}
    ).get("Item")


def op_receipts_for_patient(payload):
    require(payload, "patient_id")
    return by_partition_key(
        receipts_table, "patient_id", payload["patient_id"].strip()
    )


def op_create_receipt(payload):
    require(payload, "patient_id", "receipt_id", "method", "amount")
    patient = must_get_patient(payload["patient_id"].strip())
    receipt_id = payload["receipt_id"].strip()
    try:
        amount = int(payload["amount"])
    except (TypeError, ValueError):
        raise BusinessError("Amount must be a whole number.")
    # int() silently truncates floats coming from JSON (12.5 -> 12), so
    # reject any fractional amount explicitly.
    if isinstance(payload["amount"], float) and payload["amount"] != amount:
        raise BusinessError("Amount must be a whole number.")
    if amount <= 0:
        raise BusinessError("Amount must be greater than zero.")

    item = {
        "receipt_id": receipt_id,
        "patient_id": patient["patient_id"],
        "patient_name": patient.get("patient_name", ""),
        "method": payload["method"],
        "amount": amount,
        "date": datetime.now().strftime("%Y/%m/%d"),
    }
    # Same atomic duplicate-ID guard as create_patient.
    try:
        receipts_table.put_item(
            Item=item,
            ConditionExpression="attribute_not_exists(receipt_id)",
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            raise BusinessError(f"Receipt ID {receipt_id} already exists.")
        raise
    return item


# ---------------------------------------------------------------------------
# Medical records
# ---------------------------------------------------------------------------
def op_medical_records(payload):
    require(payload, "patient_id")
    records = by_partition_key(
        medical_records_table, "patient_id", payload["patient_id"].strip()
    )
    return sorted(records, key=lambda r: str(r.get("date", "")))


def op_add_medical_record(payload):
    require(payload, "patient_id", "diagnosis", "prescriptions", "treatment_plan")
    patient_id = payload["patient_id"].strip()
    must_get_patient(patient_id)
    now = datetime.now()
    item = {
        "record_id": f'{patient_id}-{now.strftime("%Y-%m-%d")}-{now.strftime("%H%M%S")}',
        "patient_id": patient_id,
        "diagnosis": payload["diagnosis"],
        "prescriptions": payload["prescriptions"],
        "treatment_plan": payload["treatment_plan"],
        "date": now.strftime("%Y-%m-%d"),
    }
    medical_records_table.put_item(Item=item)
    return item


def op_delete_medical_records(payload):
    require(payload, "patient_id")
    patient_id = payload["patient_id"].strip()
    records = by_partition_key(medical_records_table, "patient_id", patient_id)
    # record_id is the table's only key attribute; rows without one (should
    # not exist, but legacy data) cannot be addressed by delete_item at all,
    # so they are skipped rather than "deleted" into a no-op.
    deleted = 0
    for record in records:
        if "record_id" not in record:
            continue
        medical_records_table.delete_item(Key={"record_id": record["record_id"]})
        deleted += 1
    return {"deleted": deleted}


# ---------------------------------------------------------------------------
# Availability
# ---------------------------------------------------------------------------
def op_set_availability(payload):
    require(payload, "doctor_id", "date", "status")
    status = payload["status"].strip()
    if status not in ("block", "unblock"):
        raise BusinessError("Status must be 'block' or 'unblock'.")
    availability_table.put_item(
        Item={
            "doctor_id": payload["doctor_id"].strip(),
            "date": payload["date"].strip(),
            "status": status,
        }
    )
    return {"doctor_id": payload["doctor_id"], "date": payload["date"], "status": status}


def op_availability_for_doctor(payload):
    require(payload, "doctor_id")
    rows = by_partition_key(
        availability_table, "doctor_id", payload["doctor_id"].strip()
    )
    return sorted(rows, key=lambda r: str(r.get("date", "")))


# ---------------------------------------------------------------------------
# Nursing
# ---------------------------------------------------------------------------
def op_add_observation(payload):
    require(payload, "patient_id", "blood_pressure", "pulse", "temperature")
    patient = must_get_patient(payload["patient_id"].strip())
    item = {
        "observation_id": (
            f'{patient["patient_id"]}-{datetime.now().strftime("%Y%m%d%H%M%S")}'
        ),
        "patient_id": patient["patient_id"],
        "patient_name": patient.get("patient_name", ""),
        "blood_pressure": payload["blood_pressure"],
        "pulse": payload["pulse"],
        "temperature": payload["temperature"],
    }
    observations_table.put_item(Item=item)
    return item


def op_add_medication(payload):
    require(payload, "patient_id", "medicine", "dosage", "time_given")
    patient_id = payload["patient_id"].strip()
    must_get_patient(patient_id)
    item = {
        "medication_id": f'{patient_id}-{datetime.now().strftime("%Y%m%d%H%M%S")}',
        "patient_id": patient_id,
        "medicine": payload["medicine"],
        "dosage": payload["dosage"],
        "time_given": payload["time_given"],
    }
    medications_table.put_item(Item=item)
    return item


# ---------------------------------------------------------------------------
# AI consultation (Bedrock)
# ---------------------------------------------------------------------------
def op_consultation(payload):
    require(payload, "patient_id", "problem")
    patient_id = payload["patient_id"].strip()
    must_get_patient(patient_id)  # every other action validates; so does this
    problem = payload["problem"].strip()

    prompt = (
        "You are a helpful medical triage assistant for a clinic. A patient "
        f"(ID {patient_id}) describes the following problem: {problem}\n\n"
        "Give general, non-diagnostic guidance: what the symptom might relate "
        "to, simple self-care advice, and clear signs that mean they should "
        "see a doctor or seek emergency care. Keep it under 250 words and do "
        "not claim to provide a diagnosis."
    )

    try:
        response = bedrock.invoke_model(
            modelId=BEDROCK_MODEL_ID,
            body=json.dumps({
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": 512,
                "messages": [{"role": "user", "content": prompt}],
            }),
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code in ("AccessDeniedException", "UnauthorizedException"):
            raise BusinessError(
                "The Lambda role is not allowed to invoke Bedrock, or model "
                f"{BEDROCK_MODEL_ID} is not enabled in this account."
            )
        if code == "ValidationException":
            raise BusinessError(
                f"Bedrock rejected the request. Check BEDROCK_MODEL_ID "
                f"(currently {BEDROCK_MODEL_ID}). Detail: {exc}"
            )
        raise

    result = json.loads(response["body"].read())
    try:
        reply = result["content"][0]["text"]
    except (KeyError, IndexError, TypeError):
        raise BusinessError(f"Unexpected Bedrock response shape: {result}")
    return {"reply": reply, "model": BEDROCK_MODEL_ID}


# ---------------------------------------------------------------------------
# Routing
# ---------------------------------------------------------------------------
ROUTES = {
    "ping": lambda _payload: {"service": "clinic-serverless", "time": datetime.now().isoformat()},
    "login": op_login,
    "list_patients": op_list_patients,
    "get_patient": op_get_patient,
    "create_patient": op_create_patient,
    "update_patient": op_update_patient,
    "update_patient_contact": op_update_patient_contact,
    "appointments_for_doctor": op_appointments_for_doctor,
    "appointments_for_patient": op_appointments_for_patient,
    "schedule_appointment": op_schedule_appointment,
    "list_receipts": op_list_receipts,
    "get_receipt": op_get_receipt,
    "receipts_for_patient": op_receipts_for_patient,
    "create_receipt": op_create_receipt,
    "medical_records": op_medical_records,
    "add_medical_record": op_add_medical_record,
    "delete_medical_records": op_delete_medical_records,
    "set_availability": op_set_availability,
    "availability_for_doctor": op_availability_for_doctor,
    "add_observation": op_add_observation,
    "add_medication": op_add_medication,
    "consultation": op_consultation,
}


def lambda_handler(event, _context):
    try:
        body = json.loads(event.get("body") or "{}")
    except json.JSONDecodeError:
        return respond(400, {"ok": False, "error": "Body is not valid JSON."})

    action = body.get("action")
    payload = body.get("payload") or {}

    handler = ROUTES.get(action)
    if handler is None:
        return respond(404, {
            "ok": False,
            "error": f"Unknown action '{action}'. Known actions: {', '.join(sorted(ROUTES))}.",
        })

    try:
        data = handler(payload)
        return respond(200, {"ok": True, "data": clean(data)})
    except BusinessError as exc:
        return respond(200, {"ok": False, "error": str(exc)})
    except ClientError as exc:
        error = exc.response.get("Error", {})
        code = error.get("Code", "ClientError")
        message = error.get("Message", str(exc))
        if code == "ResourceNotFoundException":
            message = f"Table not found: {message}"
        elif code == "ValidationException":
            message = f"The table key schema does not match this request: {message}"
        return respond(200, {"ok": False, "error": f"{code}: {message}"})
    except Exception as exc:  # noqa: BLE001 - last resort, must not hide behind 500 silence
        return respond(500, {"ok": False, "error": f"{type(exc).__name__}: {exc}"})
