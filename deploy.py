"""One-command deployment for the clinic serverless backend.

Creates (or updates) everything the backend needs, using your local AWS
credentials (the standard boto3 chain, i.e. ~/.aws/credentials or environment
variables. No keys are written into any file this script produces):

  1. IAM role  clinic-serverless-role        Lambda execution role with
                                             DynamoDB + Bedrock permissions
  2. Lambda    clinic-serverless-backend     from lambda_function.py in this folder
  3. REST API  clinic-serverless-api         POST /call, API key required
  4. API key   clinic-client-key             printed at the end, paste it into
                                             serverless_config.json on the client

Usage:
    python deploy.py

Re-running is safe: existing resources are updated in place, not duplicated.
The invoke URL and API key are also saved to serverless_config.json next to
the client script, so it works out of the box.
"""

import hashlib
import json
import time
import zipfile
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

REGION = "us-east-1"
ROLE_NAME = "clinic-serverless-role"
FUNCTION_NAME = "clinic-serverless-backend"
API_NAME = "clinic-serverless-api"
STAGE_NAME = "prod"
RESOURCE_PATH = "call"
API_KEY_NAME = "clinic-client-key"
USAGE_PLAN_NAME = "clinic-client-plan"
BEDROCK_MODEL_ID = "anthropic.claude-3-haiku-20240307-v1:0"

# key_schema: (hash_key, range_key or None). gsi: (name, hash_key) or None.
# gsis: [(name, hash_key), ...] for tables that need more than one index.
TABLE_SCHEMAS = {
    "patients": {"hash": "patient_id"},
    "staff": {"hash": "username"},
    # record_id (patient-date-time) instead of patient_id: a patient may hold
    # several appointments, and a patient_id primary key would silently
    # overwrite the previous one on every new booking.
    "Appointments": {
        "hash": "record_id",
        "gsis": [("doctor_id-index", "doctor_id"), ("patient_id-index", "patient_id")],
    },
    "medicalRecord": {"hash": "record_id"},
    "receipts": {"hash": "receipt_id"},
    "availability": {"hash": "doctor_id", "range": "date"},
    "observations": {"hash": "observation_id"},
    "medications": {"hash": "medication_id"},
}
TABLES = list(TABLE_SCHEMAS)

STAFF_SEED = [
    {"username": "Sara", "role": "1", "password": "sara123"},
    {"username": "Bob", "role": "2", "password": "bob123"},
    {"username": "Charlie", "role": "3", "password": "charlie123"},
]

iam = boto3.client("iam", region_name=REGION)
lam = boto3.client("lambda", region_name=REGION)
apigw = boto3.client("apigateway", region_name=REGION)
dynamodb = boto3.resource("dynamodb", region_name=REGION)
sts = boto3.client("sts", region_name=REGION)

account_id = sts.get_caller_identity()["Account"]
TABLE_ARNS = [f"arn:aws:dynamodb:{REGION}:{account_id}:table/{name}" for name in TABLES]


def step(message):
    print(f"\n==> {message}")


def ok(message):
    print(f"    {message}")


def hash_password(password):
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# 0. DynamoDB tables + staff seed
# ---------------------------------------------------------------------------
def ensure_tables():
    step("Ensuring DynamoDB tables")
    # TableNames is a plain list of strings, not a list of dicts.
    existing = set(dynamodb.meta.client.list_tables()["TableNames"])
    for name in TABLES:
        schema = TABLE_SCHEMAS[name]
        if name in existing:
            # Warn when an old deployment has a mismatched key layout: the
            # code above will happily run against the wrong schema otherwise.
            actual = dynamodb.meta.client.describe_table(TableName=name)["Table"]["KeySchema"]
            actual_hash = next(k["AttributeName"] for k in actual if k["KeyType"] == "HASH")
            if actual_hash != schema["hash"]:
                ok(f"WARNING: {name} uses {actual_hash} as hash key but the code "
                   f"expects {schema['hash']}. Delete the table to migrate.")
            else:
                ok(f"Table {name} already exists")
            continue
        key_schema = [{"AttributeName": schema["hash"], "KeyType": "HASH"}]
        if schema.get("range"):
            key_schema.append({"AttributeName": schema["range"], "KeyType": "RANGE"})

        attribute_names = {schema["hash"]}
        if schema.get("range"):
            attribute_names.add(schema["range"])

        gsis = list(schema.get("gsis", []))
        if schema.get("gsi"):
            gsis.append(schema["gsi"])
        kwargs = {}
        if gsis:
            gsi_definitions = []
            for gsi_name, gsi_hash in gsis:
                attribute_names.add(gsi_hash)
                gsi_definitions.append({
                    "IndexName": gsi_name,
                    "KeySchema": [{"AttributeName": gsi_hash, "KeyType": "HASH"}],
                    "Projection": {"ProjectionType": "ALL"},
                })
            kwargs["GlobalSecondaryIndexes"] = gsi_definitions

        attribute_definitions = [
            {"AttributeName": attr, "AttributeType": "S"}
            for attr in sorted(attribute_names)
        ]
        dynamodb.create_table(
            TableName=name,
            KeySchema=key_schema,
            AttributeDefinitions=attribute_definitions,
            BillingMode="PAY_PER_REQUEST",
            **kwargs,
        )
        ok(f"Created table {name} ({schema['hash']}"
           + (f", {schema['range']}" if schema.get("range") else "") + ")")
    waiter = dynamodb.meta.client.get_waiter("table_exists")
    for name in TABLES:
        if name not in existing:
            waiter.wait(TableName=name)
    ok("All tables ready")


def seed_staff():
    step("Seeding staff accounts (passwords stored as SHA-256)")
    staff = dynamodb.Table("staff")
    for account in STAFF_SEED:
        if staff.get_item(Key={"username": account["username"]}).get("Item"):
            ok(f"{account['username']} already present, skipped")
            continue
        staff.put_item(Item={
            "username": account["username"],
            "role": account["role"],
            "password_sha256": hash_password(account["password"]),
        })
        ok(f"Added {account['username']} (role {account['role']})")


# ---------------------------------------------------------------------------
# 1. IAM role
# ---------------------------------------------------------------------------
def ensure_role():
    step("Ensuring IAM role")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    try:
        role = iam.get_role(RoleName=ROLE_NAME)["Role"]
        ok(f"Role {ROLE_NAME} already exists")
    except iam.exceptions.NoSuchEntityException:
        role = iam.create_role(
            RoleName=ROLE_NAME,
            AssumeRolePolicyDocument=json.dumps(trust),
            Description="Execution role for the clinic serverless backend",
        )["Role"]
        ok(f"Created role {ROLE_NAME}")

    iam.put_role_policy(
        RoleName=ROLE_NAME,
        PolicyName="clinic-backend-access",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["dynamodb:GetItem", "dynamodb:PutItem",
                               "dynamodb:UpdateItem", "dynamodb:DeleteItem",
                               "dynamodb:Query", "dynamodb:Scan"],
                    "Resource": TABLE_ARNS + [arn + "/index/*" for arn in TABLE_ARNS],
                },
                {
                    "Effect": "Allow",
                    "Action": ["bedrock:InvokeModel"],
                    "Resource": "*",
                },
            ],
        }),
    )
    ok(f"Permissions attached (DynamoDB on the {len(TABLES)} tables + Bedrock InvokeModel)")
    return role["Arn"]


# ---------------------------------------------------------------------------
# 2. Lambda function
# ---------------------------------------------------------------------------
def zip_lambda():
    source = Path(__file__).with_name("lambda_function.py")
    with zipfile.ZipFile(
        Path(__file__).with_name("lambda_function.zip"), "w",
        compression=zipfile.ZIP_DEFLATED,
    ) as bundle:
        bundle.write(source, "lambda_function.py")
    return Path(__file__).with_name("lambda_function.zip").read_bytes()


def ensure_lambda(role_arn, code_bytes):
    step("Ensuring Lambda function")
    try:
        lam.get_function(FunctionName=FUNCTION_NAME)
        lam.update_function_code(
            FunctionName=FUNCTION_NAME, ZipFile=code_bytes
        )
        lam.update_function_configuration(
            FunctionName=FUNCTION_NAME,
            Runtime="python3.13",
            Handler="lambda_function.lambda_handler",
            Timeout=30,
            MemorySize=256,
            Environment={"Variables": {"BEDROCK_MODEL_ID": BEDROCK_MODEL_ID}},
        )
        ok(f"Updated existing function {FUNCTION_NAME}")
    except lam.exceptions.ResourceNotFoundException:
        for attempt in range(5):
            try:
                lam.create_function(
                    FunctionName=FUNCTION_NAME,
                    Runtime="python3.13",
                    Role=role_arn,
                    Handler="lambda_function.lambda_handler",
                    ZipFile=code_bytes,
                    Timeout=30,
                    MemorySize=256,
                    Environment={"Variables": {"BEDROCK_MODEL_ID": BEDROCK_MODEL_ID}},
                )
                ok(f"Created function {FUNCTION_NAME}")
                break
            except ClientError as exc:
                # A freshly created role takes a few seconds to propagate.
                if "role" in str(exc).lower() and attempt < 4:
                    ok("IAM role not propagated yet, retrying in 8s ...")
                    time.sleep(8)
                else:
                    raise
        else:
            raise
    return f"arn:aws:lambda:{REGION}:{account_id}:function:{FUNCTION_NAME}"


# ---------------------------------------------------------------------------
# 3. REST API
# ---------------------------------------------------------------------------
def ensure_api(lambda_arn):
    step("Ensuring REST API")
    apis = apigw.get_rest_apis()["items"]
    api = next((a for a in apis if a["name"] == API_NAME), None)
    if api is None:
        api = apigw.create_rest_api(
            name=API_NAME,
            description="Backend for the clinic management client",
            endpointConfiguration={"types": ["REGIONAL"]},
        )
        ok(f"Created API {API_NAME}")
    else:
        ok(f"API {API_NAME} already exists")
    api_id = api["id"]

    resources = apigw.get_resources(restApiId=api_id)["items"]
    root_id = next(r["id"] for r in resources if r["path"] == "/")
    call = next((r for r in resources if r["path"] == f"/{RESOURCE_PATH}"), None)
    if call is None:
        call = apigw.create_resource(
            restApiId=api_id, parentId=root_id, pathPart=RESOURCE_PATH
        )
        ok(f"Created /{RESOURCE_PATH} resource")
    resource_id = call["id"]

    # POST method, API key required
    methods = apigw.get_method(restApiId=api_id, resourceId=resource_id,
                               httpMethod="POST") \
        if _method_exists(api_id, resource_id) else None
    if methods is None:
        apigw.put_method(
            restApiId=api_id, resourceId=resource_id, httpMethod="POST",
            authorizationType="NONE", apiKeyRequired=True,
        )
        apigw.put_method_response(
            restApiId=api_id, resourceId=resource_id, httpMethod="POST",
            statusCode="200", responseParameters={
                "method.response.header.Content-Type": False,
            },
        )
        ok("Created POST method (API key required)")
    else:
        ok("POST method already exists")

    apigw.put_integration(
        restApiId=api_id, resourceId=resource_id, httpMethod="POST",
        type="AWS_PROXY", integrationHttpMethod="POST",
        uri=f"arn:aws:apigateway:{REGION}:lambda:path/2015-03-31/functions/{lambda_arn}/invocations",
    )

    # Let API Gateway invoke the function
    source_arn = f"arn:aws:execute-api:{REGION}:{account_id}:{api_id}/*/{'POST'}/{RESOURCE_PATH}"
    try:
        lam.add_permission(
            FunctionName=FUNCTION_NAME, StatementId="apigw-invoke",
            Action="lambda:InvokeFunction",
            Principal="apigateway.amazonaws.com", SourceArn=source_arn,
        )
        ok("Granted API Gateway permission to invoke the function")
    except ClientError as exc:
        if "ResourceConflictException" in str(exc):
            ok("Invoke permission already in place")
        else:
            raise

    return api_id


def _method_exists(api_id, resource_id):
    try:
        apigw.get_method(restApiId=api_id, resourceId=resource_id, httpMethod="POST")
        return True
    except apigw.exceptions.NotFoundException:
        return False


# ---------------------------------------------------------------------------
# 4. API key + usage plan
# ---------------------------------------------------------------------------
def ensure_api_key():
    step("Ensuring API key and usage plan")
    # includeValues=True: without it, get_api_keys never returns the key's
    # value, so a re-run would crash on key["value"] below.
    keys = apigw.get_api_keys(includeValues=True, limit=500)["items"]
    key = next((k for k in keys if k.get("name") == API_KEY_NAME), None)
    if key is None:
        key = apigw.create_api_key(name=API_KEY_NAME, enabled=True)
        ok(f"Created API key {API_KEY_NAME}")
    else:
        ok(f"API key {API_KEY_NAME} already exists (value reused below)")

    plans = apigw.get_usage_plans(limit=500)["items"]
    plan = next((p for p in plans if p.get("name") == USAGE_PLAN_NAME), None)
    if plan is None:
        plan = apigw.create_usage_plan(
            name=USAGE_PLAN_NAME,
            throttle={"rateLimit": 10, "burstLimit": 20},
            quota={"limit": 5000, "period": "DAY"},
        )
    plan_id = plan["id"]
    staged = {s["apiId"] for s in apigw.get_usage_plan(
        usagePlanId=plan_id)["apiStages"]}
    return key, plan_id, staged


def bind_key_to_stage(key, plan_id, api_id, staged):
    if api_id not in staged:
        apigw.update_usage_plan(
            usagePlanId=plan_id,
            patchOperations=[{
                "op": "add", "path": "/apis/stages",
                "value": f"{api_id}/{STAGE_NAME}",
            }],
        )
    try:
        apigw.create_usage_plan_key(
            usagePlanId=plan_id, keyId=key["id"], keyType="API_KEY"
        )
    except ClientError as exc:
        if "ConflictException" not in str(exc):
            raise


# ---------------------------------------------------------------------------
# 5. Deploy stage
# ---------------------------------------------------------------------------
def deploy(api_id):
    step("Deploying to stage")
    apigw.create_deployment(restApiId=api_id, stageName=STAGE_NAME)
    url = f"https://{api_id}.execute-api.{REGION}.amazonaws.com/{STAGE_NAME}/{RESOURCE_PATH}"
    ok(f"Invoke URL: {url}")
    return url


def main():
    print("Clinic serverless backend deployment")
    print(f"region: {REGION}  account: {account_id}")

    role_arn = ensure_role()
    ensure_tables()
    seed_staff()
    code_bytes = zip_lambda()
    lambda_arn = ensure_lambda(role_arn, code_bytes)
    api_id = ensure_api(lambda_arn)
    key, plan_id, staged = ensure_api_key()
    bind_key_to_stage(key, plan_id, api_id, staged)
    url = deploy(api_id)

    # Merge into the existing config instead of overwriting it, so fields
    # the client owns (like "mode") survive a redeployment.
    config_path = Path(__file__).with_name("serverless_config.json")
    config = {}
    if config_path.exists():
        try:
            config = json.loads(config_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            pass
    config["api_url"] = url
    config["api_key"] = key["value"]
    config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")

    print("\n================ DONE ================")
    print(f"Invoke URL : {url}")
    print(f"API key    : {key['value']}")
    print(f"Saved to   : {config_path}")
    print("The client reads this file automatically. Keep the key out of git.")
    print("======================================")


if __name__ == "__main__":
    main()
