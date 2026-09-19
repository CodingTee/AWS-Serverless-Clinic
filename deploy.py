"""One-command deployment for the clinic serverless backend.

Creates (or updates) everything the backend needs, using your local AWS
credentials (the standard boto3 chain, i.e. ~/.aws/credentials or environment
variables. No keys are written into any file this script produces):

  1. IAM role      clinic-serverless-role        Lambda execution role with
                                                 DynamoDB + Bedrock + Cognito
                                                 permissions
  2. Cognito       clinic-users                  user pool + app client; staff
      User Pool    clinic-desktop-client         and patient accounts live here
  3. Lambda        clinic-serverless-backend     from lambda_function.py in this
                                                 folder, verifies Cognito JWTs
  4. REST API      clinic-serverless-api         POST /call, API key required
  5. API key       clinic-client-key             printed at the end, paste it into
                                                 serverless_config.json on the client

Usage:
    python deploy.py

Re-running is safe: existing resources are updated in place, not duplicated.
The invoke URL, API key and Cognito IDs are also saved to
serverless_config.json next to the client script, so it works out of the box.
"""

import hashlib
import json
import secrets
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

# Cognito: password policy is deliberately lenient (the seeded demo accounts
# use short passwords); everything hard (salted hashing, lockout, optional
# MFA) is Cognito's job now, not ours.
USER_POOL_NAME = "clinic-users"
APP_CLIENT_NAME = "clinic-desktop-client"
ACCESS_TOKEN_HOURS = 12  # matches the old 12-hour session token lifetime

dynamodb_c = boto3.client("dynamodb", region_name=REGION)
cognito = boto3.client("cognito-idp", region_name=REGION)
iam = boto3.client("iam", region_name=REGION)
lam = boto3.client("lambda", region_name=REGION)
apigw = boto3.client("apigateway", region_name=REGION)
dynamodb = boto3.resource("dynamodb", region_name=REGION)
sts = boto3.client("sts", region_name=REGION)

account_id = sts.get_caller_identity()["Account"]

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
# 0b. Cognito user pool, app client and accounts
# ---------------------------------------------------------------------------
def ensure_user_pool():
    step("Ensuring Cognito user pool")
    pools = cognito.list_user_pools(MaxResults=60)["UserPools"]
    pool = next((p for p in pools if p["Name"] == USER_POOL_NAME), None)
    if pool is None:
        pool = cognito.create_user_pool(
            PoolName=USER_POOL_NAME,
            Policies={"PasswordPolicy": {
                "MinimumLength": 6,
                "RequireUppercase": False,
                "RequireLowercase": False,
                "RequireNumbers": False,
                "RequireSymbols": False,
            }},
            Schema=[
                # custom:* attributes that travel inside every access token,
                # so the Lambda can map a verified token to ACTION_ROLES.
                {"Name": "role", "AttributeDataType": "String", "Mutable": True},
                {"Name": "patient_id", "AttributeDataType": "String", "Mutable": True},
            ],
            MfaConfiguration="OFF",
            # Accounts exist only because an admin (deploy.py / create_patient)
            # created them: no self sign-up, no email verification (patients
            # have no verified email in this system).
            AdminCreateUserConfig={"AllowAdminCreateUserOnly": True},
        )["UserPool"]
        ok(f"Created user pool {USER_POOL_NAME}")
    else:
        ok(f"User pool {USER_POOL_NAME} already exists")
    return pool["Id"]


def ensure_app_client(pool_id):
    step("Ensuring Cognito app client")
    clients = cognito.list_user_pool_clients(
        UserPoolId=pool_id, MaxResults=60
    )["UserPoolClients"]
    client = next((c for c in clients if c["ClientName"] == APP_CLIENT_NAME), None)
    if client is None:
        client = cognito.create_user_pool_client(
            UserPoolId=pool_id,
            ClientName=APP_CLIENT_NAME,
            GenerateSecret=False,  # desktop client: public app client
            ExplicitAuthFlows=[
                "ALLOW_USER_PASSWORD_AUTH",
                "ALLOW_REFRESH_TOKEN_AUTH",
            ],
            AccessTokenValidity=ACCESS_TOKEN_HOURS,
            RefreshTokenValidity=30,
        )["UserPoolClient"]
        ok(f"Created app client {APP_CLIENT_NAME}")
    else:
        ok(f"App client {APP_CLIENT_NAME} already exists")
    return client["ClientId"]


def seed_cognito_staff(pool_id):
    step("Seeding Cognito staff accounts")
    for account in STAFF_SEED:
        existed = True
        try:
            cognito.admin_create_user(
                UserPoolId=pool_id,
                Username=account["username"],
                UserAttributes=[
                    {"Name": "custom:role", "Value": account["role"]},
                ],
                # Must satisfy the pool's password policy; set as permanent
                # right after, so staff sign in without a first-login change.
                TemporaryPassword=account["password"],
                MessageAction="SUPPRESS",
            )
            existed = False
        except cognito.exceptions.UsernameExistsException:
            pass
        # Permanent password + role attribute: also repairs pre-existing
        # accounts whose role claim drifted from STAFF_SEED.
        cognito.admin_set_user_password(
            UserPoolId=pool_id,
            Username=account["username"],
            Password=account["password"],
            Permanent=True,
        )
        cognito.admin_update_user_attributes(
            UserPoolId=pool_id,
            Username=account["username"],
            UserAttributes=[{"Name": "custom:role", "Value": account["role"]}],
        )
        ok(f"{account['username']} (role {account['role']})"
           + (" updated" if existed else " created"))
    ok("Staff sign in with their usual username + password")


def provision_existing_patients(pool_id):
    """Give every patient already in DynamoDB a Cognito account.

    New patients get accounts automatically when a receptionist runs
    create_patient; this one-off step covers data predating Cognito. Each
    patient's temporary password is printed exactly once - the client forces
    a password change at first sign-in.
    """
    step("Provisioning Cognito accounts for existing patients")
    response = dynamodb_c.scan(TableName="patients")
    patients = response.get("Items", [])
    while "LastEvaluatedKey" in response:
        response = dynamodb_c.scan(
            TableName="patients",
            ExclusiveStartKey=response["LastEvaluatedKey"],
        )
        patients.extend(response.get("Items", []))
    if not patients:
        ok("No existing patients found")
        return
    created = 0
    for patient in patients:
        patient_id = next(
            (v["S"] for k, v in patient.items() if k == "patient_id"), None
        )
        if not patient_id:
            continue
        try:
            cognito.admin_get_user(UserPoolId=pool_id, Username=patient_id)
            ok(f"{patient_id} already has an account")
            continue
        except cognito.exceptions.UserNotFoundException:
            pass
        temporary_password = "Clinic-" + secrets.token_hex(4)
        cognito.admin_create_user(
            UserPoolId=pool_id,
            Username=patient_id,
            UserAttributes=[
                {"Name": "custom:role", "Value": "4"},
                {"Name": "custom:patient_id", "Value": patient_id},
            ],
            TemporaryPassword=temporary_password,
            MessageAction="SUPPRESS",
        )
        created += 1
        ok(f"{patient_id}: temporary password {temporary_password}")
    if not created:
        ok("All patient accounts already exist")


# ---------------------------------------------------------------------------
# 1. IAM role
# ---------------------------------------------------------------------------
def ensure_role(pool_id):
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
                {
                    # create_patient provisions the patient's Cognito login.
                    "Effect": "Allow",
                    "Action": ["cognito-idp:AdminCreateUser",
                               "cognito-idp:AdminSetUserPassword",
                               "cognito-idp:AdminUpdateUserAttributes"],
                    "Resource": f"arn:aws:cognito-idp:{REGION}:{account_id}:userpool/{pool_id}",
                },
            ],
        }),
    )
    ok(f"Permissions attached (DynamoDB on the {len(TABLES)} tables "
       "+ Bedrock InvokeModel + patient Cognito provisioning)")
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


def ensure_lambda(role_arn, code_bytes, pool_id, client_id):
    step("Ensuring Lambda function")
    # Signs the legacy session tokens (unused once Cognito is configured, but
    # kept so the backend still works if the pool env vars are removed).
    # Fresh value per run: old tokens simply stop working after a redeploy.
    session_secret = secrets.token_hex(32)
    environment = {"Variables": {
        "BEDROCK_MODEL_ID": BEDROCK_MODEL_ID,
        "SESSION_SECRET": session_secret,
        "COGNITO_USER_POOL_ID": pool_id,
        "COGNITO_CLIENT_ID": client_id,
    }}
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
            Environment=environment,
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
                    Environment=environment,
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

    ensure_tables()
    seed_staff()
    pool_id = ensure_user_pool()
    client_id = ensure_app_client(pool_id)
    seed_cognito_staff(pool_id)
    provision_existing_patients(pool_id)
    role_arn = ensure_role(pool_id)
    code_bytes = zip_lambda()
    lambda_arn = ensure_lambda(role_arn, code_bytes, pool_id, client_id)
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
    config["region"] = REGION
    config["cognito_pool_id"] = pool_id
    config["cognito_client_id"] = client_id
    config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")

    print("\n================ DONE ================")
    print(f"Invoke URL : {url}")
    print(f"API key    : {key['value']}")
    print(f"User pool  : {pool_id}")
    print(f"App client : {client_id}")
    print(f"Saved to   : {config_path}")
    print("The client reads this file automatically. Keep the key out of git.")
    print("Sign-in now goes through Amazon Cognito; patients created before")
    print("this run received temporary passwords printed above.")
    print("======================================")


if __name__ == "__main__":
    main()
