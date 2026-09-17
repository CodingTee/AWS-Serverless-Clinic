# Clinic Management System, Serverless Edition

A tkinter desktop client that never touches AWS directly: API Gateway +
Lambda + DynamoDB + Bedrock behind one authenticated endpoint, plus an
offline demo mode that runs the whole system with no AWS account at all.

Same four roles and the same seven DynamoDB tables as the original CLI project
(plus a `staff` table added for backend login), but restructured so the client
never touches AWS:

```
Desktop client (tkinter)      API Gateway (API key)      Lambda (IAM role)
HTTP POST /call  ---------->  validates key  ---------->  DynamoDB x8
{"action": "..."}                                         Bedrock (AI consult)

                       or, with no AWS account at all:

Desktop client (tkinter)  -->  DemoBackend (local)  -->  demo_data.json
```

- The client holds **no AWS credentials**. Its only secret is an API key,
  which is not an AWS credential and can be rotated in the API Gateway
  console without redeploying anything.
- DynamoDB and Bedrock are reachable **only** from the Lambda execution role.
- The AI consultation now runs inside the backend Lambda, so the client also
  no longer needs the old unauthenticated `ReplyQuestion` endpoint.
- Every AWS-facing code path is still present: the DynamoDB calls in
  `lambda_function.py`, the Bedrock `invoke_model` call, and the `requests`
  POST in the client. Switching the data source to AWS uses all of them
  unchanged. The demo mode is an addition, not a replacement.

## Screenshots

From the original September 2025 deployment on AWS, the project this
repository was rebuilt from. A few names differ from the current `deploy.py`:
the old function was `ReplyQuestion` (its unauthenticated endpoint is gone,
the AI consultation now runs inside the backend), and the `staff` table was
added afterwards for backend login.

AWS Lambda: the API Gateway trigger on the backend function, which reads
DynamoDB and calls Bedrock:

![AWS Lambda console showing the API Gateway trigger](images/aws-lambda-console.png)

DynamoDB item explorer on the `patients` table (fictional seed data):

![DynamoDB item explorer showing the patients table](images/aws-dynamodb-console.png)

## Files

| File | Purpose |
|---|---|
| `lambda_function.py` | The backend. One function, 23 routed actions (including staff login), all DynamoDB and Bedrock access, plus per-role authorization on every call. |
| `deploy.py` | Creates/updates the IAM role, Lambda, REST API, API key and stage. Run once, re-runnable. |
| `AWS Healthcare System Serverless GUI.py` | The desktop client. Talks only HTTPS to API Gateway, or to the local demo backend. |
| `serverless_config.json` | Invoke URL + API key + which data source to use. Keep the key out of git. |
| `demo_data.json` | Seed data for the offline demo (created on first run, edit or delete freely). |

## Two data sources

The sign-in screen has a **Data source** selector. **AWS is the default** (it is
the primary path of this project); the last choice is remembered in
`serverless_config.json`:

| Mode | What it does | Needs AWS? |
|---|---|---|
| **AWS (API Gateway)** (default) | The real path: HTTPS to API Gateway, which invokes the Lambda, which talks to DynamoDB and Bedrock. Requires `deploy.py` to have run. | Yes |
| **Demo (offline)** | A local `DemoBackend` implements all 23 actions with the same checks the Lambda performs (staff login, duplicate patient/receipt IDs, clashing slots, blocked dates, missing fields). Changes persist to `demo_data.json`. The AI consultation returns canned guidance instead of calling Bedrock. | No |

The screens, buttons and error dialogs are identical in both modes, so the demo
is a faithful preview of the deployed system.

### Sessions and per-role authorization

Sign-in returns a session token; every later call carries it and the backend
decides what the role may do. The enforcement lives in the backend, not the
client: a tampered client cannot read another patient's records by editing the
request.

- Roles: 1 receptionist, 2 doctor, 3 nurse, 4 patient. Each action has an
  allowed-role set (`ACTION_ROLES`, identical in both backends); anything not
  listed is rejected.
- Patients are restricted to their **own** ID: the backend compares the
  `patient_id` in each request against the token's claim, so patients cannot
  view, book or consult for anyone else, and they cannot register new patients.
- Tokens are HMAC-signed and expire after 12 hours. The signing secret is a
  Lambda environment variable generated fresh by each `deploy.py` run, so a
  redeploy invalidates old sessions.
- Patients sign in with their ID only (no password, same as the original
  system) via a `patient_login` action that issues their token.

The AWS path is the same model one step up: with a Cognito User Pool
authorizer the JWT claims would replace the hand-rolled token, and the
permission matrix would stay exactly where it is (see the notes at the end).

### Sign-in accounts

Staff accounts live in a `staff` table in **both** data stores (`demo_data.json`
for demo; a DynamoDB `staff` table for AWS, created and seeded by
`deploy.py`), with passwords stored as SHA-256 hashes. The client source holds
no accounts at all: signing in is a `login` call to the backend, and patients
sign in by ID via `patient_login`. Both issue the session token described
above. The honest upgrade path is a Cognito User Pool
(salted adaptive hashing, MFA, per-user tokens), which would replace the
hand-rolled `login` action without touching the client (see the notes at the
end).

| Role | Sign in with | Seeded data |
|---|---|---|
| Receptionist | `Sara` / `sara123` | 3 patients, 2 receipts |
| Doctor | `Bob` / `bob123` | doctor ID `D01` has 2 appointments, 1 blocked date |
| Nurse | `Charlie` / `charlie123` | 1 observation and 1 medication on record |
| Patient | patient ID `B01` (no password) | 1 medical record, 1 appointment, 1 receipt |

Seeded dates are generated relative to the day you first run it, so
appointments always land a few days in the future. Delete `demo_data.json` to
regenerate the seed.

## Deploy (one command)

Local credentials must be configured first (`aws configure` or
`%USERPROFILE%\.aws\credentials`), because the deploy script itself uses them.

```
python deploy.py
```

It prints the invoke URL and API key, and saves both to
`serverless_config.json`. Re-running updates existing resources in place.

## Run the client

```
python "AWS Healthcare System Serverless GUI.py"
```

It starts on the AWS data source. To point it at a real deployment, run
`deploy.py`, which writes the invoke URL and API key into
`serverless_config.json`; or press **Configure endpoint** to paste them
manually. To try the system without any AWS account, switch **Data source** to
*Demo (offline, no AWS)*: the choice is remembered for next time.
**Test connection** sends a `ping` and confirms which backend answered.

## Cost and limits

- API key usage plan: 10 requests/second, 5000 requests/day (throttle config
  is in `deploy.py`).
- Lambda: 256 MB, 30 s timeout (the AI consultation is the slow path).
- Everything scales to zero; idle cost is 0.

## Notes for the future

- Per-role authorization is now enforced by the backend on every call. The
  next step up is a Cognito User Pool authorizer on API Gateway: real user
  accounts with salted adaptive hashing and MFA, JWT claims instead of the
  hand-rolled token, and per-user API access instead of a shared API key.
  The permission matrix would not need to move.
- Bedrock model is set via the `BEDROCK_MODEL_ID` environment variable on the
  Lambda (`deploy.py` picks the default). Enable the model in the Bedrock
  console before using the consultation feature.
- The Lambda code and the demo backend are deliberately kept in step: same
  action names, same validation messages, same authorization matrix. If you
  add an action, add it to both (plus `ROUTES` and `ACTION_ROLES` in each) or
  the two modes will drift apart.
