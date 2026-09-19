"""Clinic Management System, serverless edition (tkinter client).

Same screens as "AWS Healthcare System GUI.py", but this version NEVER touches
AWS directly. Every operation is an HTTPS POST to one API Gateway endpoint:

    POST {api_url}
    headers:  x-api-key: <key from serverless_config.json>
    body:     {"action": "...", "payload": {...}}

The backend (lambda_function.py in the serverless folder) does all DynamoDB
and Bedrock work under an IAM execution role. This client holds no AWS
credentials at all: the only secret it needs is the API key, which is not an
AWS credential and can be rotated from the API Gateway console without
touching the Lambda or the tables.

Two data sources, switchable on the sign-in screen:

  * Demo (offline): a local DemoBackend stands in for API Gateway + Lambda.
    It implements every action with the same checks the Lambda performs
    (duplicate patient/receipt IDs, clashing slots, blocked dates) and seeds
    one or two test characters per role, persisting changes to
    demo_data.json. Use this when no AWS account is available.
  * AWS (API Gateway): the real thing. Requires deploy.py to have been run
    and serverless_config.json to hold the invoke URL and API key.

Run:
    python "AWS Healthcare System Serverless GUI.py"
"""

from __future__ import annotations

import hashlib
import base64
import json
import queue
import secrets
import threading
import time
import traceback
from datetime import datetime, timedelta
from pathlib import Path

import requests
import tkinter as tk
import tkinter.font as tkfont
from tkinter import ttk, messagebox

CONFIG_FILE = Path(__file__).with_name("serverless_config.json")

# No accounts live in this file. Staff sign-in goes through the backend
# ("login" action: demo -> demo_data.json staff table, AWS -> DynamoDB staff
# table); patients sign in with their patient ID. The proper long-term
# replacement for the password check is a Cognito User Pool.

ROLE_LABELS = {"1": "Receptionist", "2": "Doctor", "3": "Nurse", "4": "Patient"}


def font(size=10, bold=False):
    family = tkfont.nametofont("TkDefaultFont").actual("family")
    return (family, size, "bold" if bold else "normal")


def mono_font(size=10):
    return (tkfont.nametofont("TkFixedFont").actual("family"), size)


# ---------------------------------------------------------------------------
# Dark dashboard theme: deep navy surfaces with cyan accents, in the style of
# a big-screen operations dashboard.
# ---------------------------------------------------------------------------
BG = "#0a1a2f"          # window background
PANEL = "#10263f"       # card / table surface
FIELD = "#0c2138"       # entry and tree background
EDGE = "#1d4e6e"        # panel border
ACCENT = "#22d3ee"      # cyan accent (titles, highlights)
BUTTON_BG = "#0e7490"   # normal button
BUTTON_HI = "#0891b2"   # hovered button
BUTTON_DN = "#155e75"   # pressed button
TEXT = "#e8f4ff"        # primary text
MUTED = "#8fb3cc"       # secondary text


def apply_theme(root):
    """Configure ttk styles so every screen uses the dark palette."""
    family = tkfont.nametofont("TkDefaultFont").actual("family")
    base = (family, 10)
    root.configure(background=BG)

    style = ttk.Style(root)
    style.theme_use("clam")
    style.configure(".", background=BG, foreground=TEXT,
                    font=base, borderwidth=0, focuscolor=ACCENT)

    style.configure("TFrame", background=BG)
    style.configure("TLabel", background=BG, foreground=TEXT)
    style.configure("Muted.TLabel", foreground=MUTED)
    style.configure("Title.TLabel", foreground=ACCENT,
                    font=(family, 20, "bold"))
    style.configure("H1.TLabel", foreground=ACCENT,
                    font=(family, 17, "bold"))
    style.configure("Status.TLabel", background=PANEL, foreground=MUTED,
                    padding=(8, 4))

    # Cards: the sign-in panel and similar surfaces.
    style.configure("Card.TFrame", background=PANEL, relief="solid",
                    borderwidth=1, bordercolor=EDGE)
    style.configure("Card.TLabel", background=PANEL, foreground=TEXT)
    style.configure("CardMuted.TLabel", background=PANEL, foreground=MUTED)

    style.configure("TLabelframe", background=BG, bordercolor=EDGE)
    style.configure("TLabelframe.Label", background=BG, foreground=ACCENT,
                    font=(family, 10, "bold"))

    style.configure("TButton", background=BUTTON_BG, foreground="#ffffff",
                    padding=(12, 6), borderwidth=0, font=base)
    style.map("TButton",
              background=[("pressed", BUTTON_DN), ("active", BUTTON_HI),
                          ("disabled", "#334155")],
              foreground=[("disabled", "#94a3b8")])

    style.configure("TEntry", fieldbackground=FIELD, foreground=TEXT,
                    insertcolor=ACCENT, bordercolor=EDGE, lightcolor=EDGE,
                    darkcolor=EDGE, padding=4)
    style.map("TEntry", bordercolor=[("focus", ACCENT)],
              lightcolor=[("focus", ACCENT)], darkcolor=[("focus", ACCENT)])

    style.configure("TCombobox", fieldbackground=FIELD, background=FIELD,
                    foreground=TEXT, arrowcolor=ACCENT, bordercolor=EDGE,
                    lightcolor=EDGE, darkcolor=EDGE, padding=4)
    style.map("TCombobox",
              fieldbackground=[("readonly", FIELD)],
              foreground=[("readonly", TEXT)],
              bordercolor=[("focus", ACCENT)])
    root.option_add("*TCombobox*Listbox.background", FIELD)
    root.option_add("*TCombobox*Listbox.foreground", TEXT)
    root.option_add("*TCombobox*Listbox.selectBackground", BUTTON_BG)
    root.option_add("*TCombobox*Listbox.selectForeground", "#ffffff")

    style.configure("Treeview", background=FIELD, fieldbackground=FIELD,
                    foreground=TEXT, rowheight=26, bordercolor=EDGE)
    style.map("Treeview",
              background=[("selected", BUTTON_BG)],
              foreground=[("selected", "#ffffff")])
    style.configure("Treeview.Heading", background=PANEL, foreground=ACCENT,
                    font=(family, 10, "bold"), borderwidth=0)
    style.map("Treeview.Heading", background=[("active", PANEL)])

    style.configure("TScrollbar", background=FIELD, troughcolor=BG,
                    bordercolor=BG, arrowcolor=MUTED)
    style.map("TScrollbar", background=[("active", EDGE)])

    # Message boxes inherit the OS look; dialogs built from ttk widgets
    # (FormDialog, TableWindow) pick up the dark theme automatically.


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------
class MissingConfigError(Exception):
    def __init__(self, message=""):
        super().__init__(message or "No endpoint configured yet.")
        self.message = self.args[0]


class ApiServerError(Exception):
    """The backend answered with ok=false and a human readable message."""


class NewPasswordRequired(Exception):
    """Cognito issued a NEW_PASSWORD_REQUIRED challenge (first sign-in).

    Carries the challenge session and username so the login screen can show
    a "choose a new password" dialog and complete the sign-in.
    """

    def __init__(self, session, username):
        super().__init__("Cognito requires a new password for this account.")
        self.session = session
        self.username = username


def describe_error(exc):
    """Turn any client-side exception into something worth reading."""
    if isinstance(exc, MissingConfigError):
        return str(exc)
    if isinstance(exc, ApiServerError):
        return f"The backend refused the request:\n\n{exc}"
    if isinstance(exc, requests.exceptions.HTTPError):
        status = exc.response.status_code if exc.response is not None else "?"
        if status in (401, 403):
            return (
                f"HTTP {status}: the API key was rejected.\n\n"
                "Check the api_key value in serverless_config.json against the "
                "key shown by deploy.py (or create a new one in the API "
                "Gateway console)."
            )
        return f"HTTP {status} from API Gateway.\n\n{exc}"
    if isinstance(exc, requests.exceptions.ConnectionError):
        return (
            "Cannot reach the API endpoint.\n\n"
            "Check the network and the api_url value in serverless_config.json."
        )
    if isinstance(exc, requests.exceptions.Timeout):
        return (
            "The request timed out. The AI consultation can take up to 30 "
            "seconds on a cold Lambda; other actions should be fast, so a "
            "timeout usually means the API URL is wrong."
        )
    if isinstance(exc, ValueError):
        # Business rules (duplicate ID, wrong password, ...) raise ValueError
        # with an already human-readable message.
        return str(exc)
    return f"{type(exc).__name__}: {exc}"


def receipt_text(receipt, patient):
    return (
        "***** Receipt *****\n"
        f"Receipt ID: {receipt.get('receipt_id')}\n"
        f"Patient's ID: {patient.get('patient_id')}\n"
        f"Patient's name: {patient.get('patient_name')}\n"
        f"Patient's IC number: {patient.get('patient_IC')}\n"
        f"Patient's address: {patient.get('patient_address')}\n"
        f"Patient's contact number: {patient.get('patient_number')}\n"
        f"Payment method: {receipt.get('method')}\n"
        f"Payment amount: RM{receipt.get('amount')}\n"
        f"Payment date: {receipt.get('date')}\n"
    )


# ---------------------------------------------------------------------------
# Data layer: one HTTPS call per operation, nothing else
# ---------------------------------------------------------------------------
class ApiClient:
    def __init__(self):
        self.api_url = None
        self.api_key = None
        # Amazon Cognito user pool the client authenticates against directly
        # (AWS mode). Written by deploy.py; empty = legacy/demo behaviour.
        self.cognito_pool_id = None
        self.cognito_client_id = None
        self.region = "us-east-1"
        self._token = None  # session token issued by login/patient_login
        self.load_config()

    # -- configuration -----------------------------------------------------
    def load_config(self):
        if CONFIG_FILE.exists():
            try:
                config = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                # Corrupt config file: start unconfigured instead of crashing
                # at import time (read_mode and save_config already tolerate
                # this; load_config was the odd one out).
                return
            self.api_url = config.get("api_url") or None
            self.api_key = config.get("api_key") or None
            self.cognito_pool_id = config.get("cognito_pool_id") or None
            self.cognito_client_id = config.get("cognito_client_id") or None
            self.region = config.get("region") or "us-east-1"

    def save_config(self, api_url, api_key):
        self.api_url = api_url.strip()
        self.api_key = api_key.strip()
        config = {}
        if CONFIG_FILE.exists():
            try:
                config = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                pass
        config["api_url"] = self.api_url
        config["api_key"] = self.api_key
        CONFIG_FILE.write_text(json.dumps(config, indent=2), encoding="utf-8")

    def ensure_configured(self):
        if not self.api_url or not self.api_key:
            raise MissingConfigError()

    @property
    def endpoint_label(self):
        if self.api_url:
            return self.api_url.split("//")[-1]
        return "endpoint not configured"

    # -- transport ---------------------------------------------------------
    def call(self, action, timeout=35, **payload):
        self.ensure_configured()
        if self._token:
            payload = {**payload, "token": self._token}
        response = requests.post(
            self.api_url,
            json={"action": action, "payload": payload},
            headers={"x-api-key": self.api_key},
            timeout=timeout,
        )
        response.raise_for_status()
        result = response.json()
        if not result.get("ok"):
            raise ApiServerError(result.get("error", "unknown backend error"))
        return result.get("data")

    # -- auth --------------------------------------------------------------
    @property
    def cognito_ready(self):
        return bool(self.cognito_pool_id and self.cognito_client_id)

    def _ensure_cognito(self):
        if not self.cognito_ready:
            raise MissingConfigError(
                "No Cognito user pool configured.\n\n"
                "Run deploy.py first: it creates the user pool and saves "
                "cognito_pool_id / cognito_client_id into "
                "serverless_config.json."
            )

    def _cognito_call(self, target, body):
        """Call the Cognito Identity Provider HTTP API (no SDK needed)."""
        url = f"https://cognito-idp.{self.region}.amazonaws.com/"
        response = requests.post(
            url,
            json=body,
            headers={
                "Content-Type": "application/x-amz-json-1.1",
                "X-Amz-Target": f"AWSCognitoIdentityProviderService.{target}",
            },
            timeout=15,
        )
        try:
            data = response.json()
        except ValueError:
            data = {}
        if not response.ok:
            code = data.get("__type", "").split("#")[-1]
            message = data.get("message") or f"Cognito error (HTTP {response.status_code})"
            if code in ("NotAuthorizedException", "UserNotFoundException"):
                raise ValueError(
                    "Incorrect username or password."
                    if code == "NotAuthorizedException"
                    else "No account with that username."
                )
            raise ApiServerError(message)
        return data

    @staticmethod
    def _decode_jwt_payload(token):
        """Read the middle segment of a JWT (payload only, no verification;
        it arrived over TLS straight from Cognito). Used for display fields
        like the role and username claims."""
        segment = token.split(".")[1]
        segment += "=" * (-len(segment) % 4)
        return json.loads(base64.urlsafe_b64decode(segment))

    def _cognito_sign_in(self, username, password):
        """USER_PASSWORD_AUTH sign-in, returns the same shape as the old
        backend login so the screens do not change."""
        self._ensure_cognito()
        auth = self._cognito_call("InitiateAuth", {
            "AuthFlow": "USER_PASSWORD_AUTH",
            "AuthParameters": {"USERNAME": username, "PASSWORD": password},
            "ClientId": self.cognito_client_id,
        })
        if auth.get("ChallengeName") == "NEW_PASSWORD_REQUIRED":
            raise NewPasswordRequired(auth.get("Session"), username)
        token = auth["AuthenticationResult"]["AccessToken"]
        claims = self._decode_jwt_payload(token)
        return {
            "role": str(claims.get("custom:role") or ""),
            "display_name": claims.get("username", username),
            "token": token,
        }

    def complete_new_password(self, username, new_password, session):
        """Finish a NEW_PASSWORD_REQUIRED challenge (first patient sign-in)."""
        auth = self._cognito_call("RespondToAuthChallenge", {
            "ChallengeName": "NEW_PASSWORD_REQUIRED",
            "Session": session,
            "ChallengeResponses": {
                "USERNAME": username,
                "NEW_PASSWORD": new_password,
            },
            "ClientId": self.cognito_client_id,
        })
        token = auth["AuthenticationResult"]["AccessToken"]
        claims = self._decode_jwt_payload(token)
        return {
            "role": str(claims.get("custom:role") or ""),
            "display_name": claims.get("username", username),
            "token": token,
        }

    def login(self, username, password, role):
        result = self._cognito_sign_in(username, password)
        if result["role"] != str(role):
            raise ValueError("This account belongs to a different role.")
        self._token = result["token"]
        return result

    def patient_login(self, patient_id, password=""):
        result = self._cognito_sign_in(patient_id, password)
        if result["role"] != "4":
            raise ValueError("This account is not a patient account.")
        self._token = result["token"]
        return {"patient_id": patient_id, "role": "4", "token": result["token"]}

    # -- patients ----------------------------------------------------------
    def get_patient(self, patient_id):
        return self.call("get_patient", patient_id=patient_id)

    def list_patients(self):
        return self.call("list_patients")

    def create_patient(self, data):
        return self.call("create_patient", **data)

    def update_patient(self, patient_id, data):
        return self.call("update_patient", patient_id=patient_id, **data)

    def update_patient_contact(self, patient_id, address, contact_number):
        return self.call(
            "update_patient_contact",
            patient_id=patient_id,
            patient_address=address,
            patient_number=contact_number,
        )

    # -- appointments ------------------------------------------------------
    def appointments_for_doctor(self, doctor_id):
        return self.call("appointments_for_doctor", doctor_id=doctor_id)

    def appointments_for_patient(self, patient_id):
        return self.call("appointments_for_patient", patient_id=patient_id)

    def schedule_appointment(self, doctor_id, date, time, patient_id):
        # Duplicate-slot and blocked-date checks happen in the backend.
        return self.call(
            "schedule_appointment",
            doctor_id=doctor_id, date=date, time=time, patient_id=patient_id,
        )

    # -- receipts ----------------------------------------------------------
    def list_receipts(self):
        return self.call("list_receipts")

    def get_receipt(self, receipt_id):
        return self.call("get_receipt", receipt_id=receipt_id)

    def receipts_for_patient(self, patient_id):
        return self.call("receipts_for_patient", patient_id=patient_id)

    def create_receipt(self, receipt_id, patient, method, amount):
        return self.call(
            "create_receipt",
            receipt_id=receipt_id,
            patient_id=patient["patient_id"],
            method=method,
            amount=amount,
        )

    # -- medical records ---------------------------------------------------
    def medical_records(self, patient_id):
        return self.call("medical_records", patient_id=patient_id)

    def add_medical_record(self, patient_id, diagnosis, prescriptions, treatment_plan):
        return self.call(
            "add_medical_record",
            patient_id=patient_id,
            diagnosis=diagnosis,
            prescriptions=prescriptions,
            treatment_plan=treatment_plan,
        )

    def delete_medical_records(self, patient_id):
        result = self.call("delete_medical_records", patient_id=patient_id)
        return result.get("deleted", 0) if isinstance(result, dict) else 0

    # -- availability ------------------------------------------------------
    def set_availability(self, doctor_id, date, status):
        return self.call(
            "set_availability", doctor_id=doctor_id, date=date, status=status
        )

    def availability_for_doctor(self, doctor_id):
        return self.call("availability_for_doctor", doctor_id=doctor_id)

    # -- nursing -----------------------------------------------------------
    def add_observation(self, patient_id, blood_pressure, pulse, temperature):
        return self.call(
            "add_observation",
            patient_id=patient_id,
            blood_pressure=blood_pressure,
            pulse=pulse,
            temperature=temperature,
        )

    def add_medication(self, patient_id, medicine, dosage, time_given):
        return self.call(
            "add_medication",
            patient_id=patient_id,
            medicine=medicine,
            dosage=dosage,
            time_given=time_given,
        )

    # -- AI consultation ---------------------------------------------------
    def request_consultation(self, patient_id, problem, timeout=60):
        return self.call(
            "consultation", timeout=timeout,
            patient_id=patient_id, problem=problem,
        )


# ---------------------------------------------------------------------------
# Demo backend: a local stand-in for API Gateway + Lambda
# ---------------------------------------------------------------------------
# The AWS paths above stay untouched; this class exists so the whole system
# can be demonstrated with no AWS account. Every action mirrors the Lambda
# implementation in lambda_function.py, including the server-side checks.
def _hash_password(password):
    """SHA-256 hex digest. Demo-grade hashing: better than plaintext, but a
    real deployment would use Cognito (salted, server-side)."""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def _demo_seed():
    today = datetime.now()

    def day(offset):
        return (today + timedelta(days=offset)).strftime("%Y/%m/%d")

    def day_dash(offset):
        return (today + timedelta(days=offset)).strftime("%Y-%m-%d")

    return {
        "staff": [
            {"username": "Sara", "role": "1", "password_sha256": _hash_password("sara123")},
            {"username": "Bob", "role": "2", "password_sha256": _hash_password("bob123")},
            {"username": "Charlie", "role": "3", "password_sha256": _hash_password("charlie123")},
        ],
        "patients": [
            {"patient_id": "B01", "patient_name": "Aisyah binti Ahmad",
             "patient_IC": "010101-01-0101", "patient_address": "12, Jalan Kenari, Cyberjaya",
             "patient_number": "012-345 6789", "patient_BOD": "2001/01/01"},
            {"patient_id": "B02", "patient_name": "Daniel Wong",
             "patient_IC": "020202-02-0202", "patient_address": "88, Jalan Bunga Raya, Puchong",
             "patient_number": "011-2233 4455", "patient_BOD": "2002/02/02"},
            {"patient_id": "B03", "patient_name": "Nurul Huda",
             "patient_IC": "030303-03-0303", "patient_address": "5, Jalan Saujana, Shah Alam",
             "patient_number": "013-9876 5432", "patient_BOD": "2003/03/03"},
        ],
        "Appointments": [
            {"record_id": f"B01-{day(2)}-10:00", "doctor_id": "D01",
             "appointment_date": day(2), "appointment_time": "10:00",
             "patient_id": "B01", "patient_name": "Aisyah binti Ahmad"},
            {"record_id": f"B02-{day(3)}-14:30", "doctor_id": "D01",
             "appointment_date": day(3), "appointment_time": "14:30",
             "patient_id": "B02", "patient_name": "Daniel Wong"},
            {"record_id": f"B03-{day(4)}-09:00", "doctor_id": "D02",
             "appointment_date": day(4), "appointment_time": "09:00",
             "patient_id": "B03", "patient_name": "Nurul Huda"},
        ],
        "medicalRecord": [
            {"record_id": "B01-" + day_dash(-7) + "-090000", "patient_id": "B01",
             "diagnosis": "Acute pharyngitis", "prescriptions": "Paracetamol 500mg, 3 times daily",
             "treatment_plan": "Rest and drink plenty of water", "date": day_dash(-7)},
            {"record_id": "B02-" + day_dash(-3) + "-110000", "patient_id": "B02",
             "diagnosis": "Mild gastritis", "prescriptions": "Antacid, after meals",
             "treatment_plan": "Avoid spicy food", "date": day_dash(-3)},
        ],
        "receipts": [
            {"receipt_id": "R01", "patient_id": "B01", "patient_name": "Aisyah binti Ahmad",
             "method": "Cash", "amount": 120, "date": day(0)},
            {"receipt_id": "R02", "patient_id": "B02", "patient_name": "Daniel Wong",
             "method": "Bank", "amount": 250, "date": day(-1)},
        ],
        "availability": [
            {"doctor_id": "D01", "date": day(9), "status": "block"},
        ],
        "observations": [
            {"observation_id": "B01-" + day_dash(-7) + "-091500", "patient_id": "B01",
             "patient_name": "Aisyah binti Ahmad", "blood_pressure": "118/76",
             "pulse": "78", "temperature": "37.1"},
        ],
        "medications": [
            {"medication_id": "B01-" + day_dash(-7) + "-093000", "patient_id": "B01",
             "medicine": "Paracetamol", "dosage": "500mg", "time_given": "09:30"},
        ],
    }


class DemoBackend:
    """Implements the same interface as ApiClient, but locally.

    All 23 actions the Lambda supports are reproduced here with the same
    validation (duplicate IDs, clashing slots, blocked dates, missing fields),
    so switching between demo and AWS changes nothing about how the screens
    behave. Data persists to demo_data.json; delete that file to reset.
    """

    mode = "demo"

    # -- per-role authorization: keep in step with lambda_function.py ------
    # Roles: 1 receptionist, 2 doctor, 3 nurse, 4 patient.
    PRE_AUTH_ACTIONS = {"ping", "login", "patient_login"}
    ACTION_ROLES = {
        "list_patients": {"1"},
        "get_patient": {"1", "2", "3", "4"},
        "create_patient": {"1"},
        "update_patient": {"1"},
        "update_patient_contact": {"1", "4"},
        "schedule_appointment": {"1", "4"},
        "appointments_for_doctor": {"2", "3"},
        "appointments_for_patient": {"4"},
        "list_receipts": {"1"},
        "get_receipt": {"1"},
        "receipts_for_patient": {"4"},
        "create_receipt": {"1"},
        "medical_records": {"2", "3", "4"},
        "add_medical_record": {"2"},
        "delete_medical_records": {"2"},
        "set_availability": {"2", "3"},
        "availability_for_doctor": {"2", "3"},
        "add_observation": {"3"},
        "add_medication": {"3"},
        "consultation": {"4"},
    }
    PATIENT_OWN_ACTIONS = {
        "get_patient",
        "update_patient_contact",
        "schedule_appointment",
        "appointments_for_patient",
        "receipts_for_patient",
        "medical_records",
        "consultation",
    }

    def __init__(self):
        self.store_path = Path(__file__).with_name("demo_data.json")
        self._lock = threading.Lock()  # serialize read-modify-write handlers
        self._token = None             # current session token, set on login
        self.sessions = {}             # token -> {"role", "patient_id"}
        if self.store_path.exists():
            self.data = json.loads(self.store_path.read_text(encoding="utf-8"))
        else:
            self.data = _demo_seed()
            self.save()
        # Migration: files written before staff accounts moved into the store.
        if not self.data.get("staff"):
            self.data["staff"] = _demo_seed()["staff"]
            self.save()

    def save(self):
        self.store_path.write_text(
            json.dumps(self.data, indent=2, ensure_ascii=False), encoding="utf-8"
        )

    @property
    def endpoint_label(self):
        return f"demo data ({self.store_path.name})"

    # -- transport: same shape as the Lambda's ROUTES ----------------------
    def call(self, action, timeout=35, **payload):
        handler = self.ROUTES.get(action)
        if handler is None:
            raise ValueError(f"Unknown action '{action}'.")
        if self._token:
            payload = {**payload, "token": self._token}
        time.sleep(0.25)  # simulate network + Lambda latency
        # Each async call runs on its own thread; without this lock two
        # overlapping writes could lose each other's changes in demo_data.json.
        with self._lock:
            if action not in self.PRE_AUTH_ACTIONS:
                self._enforce_access(action, payload)
            return handler(self, payload)

    def _enforce_access(self, action, payload):
        """Mirror the Lambda's enforce_access: token -> role -> own-only."""
        session = self.sessions.get(payload.pop("token", None))
        if session is None:
            raise ValueError("Your session has expired. Sign in again.")
        allowed = self.ACTION_ROLES.get(action)
        if allowed is None or session["role"] not in allowed:
            raise ValueError("Your role is not authorized for this action.")
        if session["role"] == "4" and action in self.PATIENT_OWN_ACTIONS:
            requested = str(payload.get("patient_id", "")).strip()
            if requested != session["patient_id"]:
                raise ValueError("Patients may only access their own records.")

    # -- semantic methods: same signatures as ApiClient --------------------
    def login(self, username, password, role):
        result = self.call("login", username=username, password=password, role=role)
        self._token = result["token"]
        return result

    def patient_login(self, patient_id, password=""):
        # Demo has no Cognito: the password (typed for AWS mode) is ignored
        # and the ID-only sign-in of the original system applies.
        result = self.call("patient_login", patient_id=patient_id)
        self._token = result["token"]
        return result

    def get_patient(self, patient_id):
        return self.call("get_patient", patient_id=patient_id)

    def list_patients(self):
        return self.call("list_patients")

    def create_patient(self, data):
        return self.call("create_patient", **data)

    def update_patient(self, patient_id, data):
        return self.call("update_patient", patient_id=patient_id, **data)

    def update_patient_contact(self, patient_id, address, contact_number):
        return self.call(
            "update_patient_contact",
            patient_id=patient_id,
            patient_address=address,
            patient_number=contact_number,
        )

    def appointments_for_doctor(self, doctor_id):
        return self.call("appointments_for_doctor", doctor_id=doctor_id)

    def appointments_for_patient(self, patient_id):
        return self.call("appointments_for_patient", patient_id=patient_id)

    def schedule_appointment(self, doctor_id, date, time, patient_id):
        return self.call(
            "schedule_appointment",
            doctor_id=doctor_id, date=date, time=time, patient_id=patient_id,
        )

    def list_receipts(self):
        return self.call("list_receipts")

    def get_receipt(self, receipt_id):
        return self.call("get_receipt", receipt_id=receipt_id)

    def receipts_for_patient(self, patient_id):
        return self.call("receipts_for_patient", patient_id=patient_id)

    def create_receipt(self, receipt_id, patient, method, amount):
        return self.call(
            "create_receipt",
            receipt_id=receipt_id,
            patient_id=patient["patient_id"],
            method=method,
            amount=amount,
        )

    def medical_records(self, patient_id):
        return self.call("medical_records", patient_id=patient_id)

    def add_medical_record(self, patient_id, diagnosis, prescriptions, treatment_plan):
        return self.call(
            "add_medical_record",
            patient_id=patient_id,
            diagnosis=diagnosis,
            prescriptions=prescriptions,
            treatment_plan=treatment_plan,
        )

    def delete_medical_records(self, patient_id):
        result = self.call("delete_medical_records", patient_id=patient_id)
        return result.get("deleted", 0) if isinstance(result, dict) else 0

    def set_availability(self, doctor_id, date, status):
        return self.call(
            "set_availability", doctor_id=doctor_id, date=date, status=status
        )

    def availability_for_doctor(self, doctor_id):
        return self.call("availability_for_doctor", doctor_id=doctor_id)

    def add_observation(self, patient_id, blood_pressure, pulse, temperature):
        return self.call(
            "add_observation",
            patient_id=patient_id,
            blood_pressure=blood_pressure,
            pulse=pulse,
            temperature=temperature,
        )

    def add_medication(self, patient_id, medicine, dosage, time_given):
        return self.call(
            "add_medication",
            patient_id=patient_id,
            medicine=medicine,
            dosage=dosage,
            time_given=time_given,
        )

    def request_consultation(self, patient_id, problem, timeout=60):
        return self.call(
            "consultation", timeout=timeout,
            patient_id=patient_id, problem=problem,
        )

    # -- helpers -----------------------------------------------------------
    def _require(self, payload, *fields):
        # 0 and False are valid values, so don't use a truthiness test here.
        missing = [
            f for f in fields
            if payload.get(f) is None or str(payload.get(f)).strip() == ""
        ]
        if missing:
            raise ValueError(f"Missing required field(s): {', '.join(missing)}")

    def _find(self, table, **match):
        return next(
            (item for item in self.data[table]
             if all(str(item.get(k, "")).strip() == str(v).strip() for k, v in match.items())),
            None,
        )

    def _filter(self, table, key, value):
        return [item for item in self.data[table]
                if str(item.get(key, "")).strip() == str(value).strip()]

    def _must_get_patient(self, patient_id):
        patient = self._find("patients", patient_id=patient_id)
        if not patient:
            raise ValueError(f"Patient {patient_id} was not found.")
        return patient

    # -- auth --------------------------------------------------------------
    # Mirrors Lambda's op_login: username is an exact (case-sensitive)
    # DynamoDB get_item key, so demo behaves identically until Cognito.
    def op_login(self, payload):
        self._require(payload, "username", "password", "role")
        username = str(payload["username"]).strip()
        role = str(payload["role"]).strip()
        account = next(
            (s for s in self.data.get("staff", [])
             if str(s.get("username", "")).strip() == username),
            None,
        )
        if account is None:
            raise ValueError("No staff account with that username.")
        if account.get("password_sha256") != _hash_password(str(payload["password"])):
            raise ValueError("Incorrect password.")
        if str(account.get("role")) != role:
            raise ValueError("This account belongs to a different role.")
        token = secrets.token_hex(16)
        self.sessions[token] = {"role": role, "patient_id": None}
        return {"role": role, "display_name": account["username"], "token": token}

    def op_patient_login(self, payload):
        # Mirrors Lambda's op_patient_login: ID-only sign-in that issues a
        # role-4 token so later calls are checked against it server-side.
        self._require(payload, "patient_id")
        patient_id = str(payload["patient_id"]).strip()
        patient = self._must_get_patient(patient_id)
        token = secrets.token_hex(16)
        self.sessions[token] = {"role": "4", "patient_id": patient_id}
        return {
            "patient_id": patient_id,
            "patient_name": patient.get("patient_name", patient_id),
            "role": "4",
            "token": token,
        }

    # -- patients ----------------------------------------------------------
    def op_list_patients(self, _payload):
        return [dict(item) for item in self.data["patients"]]

    def op_get_patient(self, payload):
        patient = self._find("patients", patient_id=payload["patient_id"])
        if patient is None:
            # Another instance may have rewritten the file since we loaded
            # it; reload once before giving up.
            if self.store_path.exists():
                self.data = json.loads(self.store_path.read_text(encoding="utf-8"))
                patient = self._find("patients", patient_id=payload["patient_id"])
        return dict(patient) if patient else None

    def op_create_patient(self, payload):
        self._require(payload, "patient_id", "patient_name", "patient_IC",
                      "patient_address", "patient_number", "patient_BOD")
        patient_id = payload["patient_id"].strip()
        if self._find("patients", patient_id=patient_id):
            raise ValueError(f"Patient ID {patient_id} already exists.")
        self.data["patients"].append({
            "patient_id": patient_id,
            "patient_name": payload["patient_name"],
            "patient_IC": payload["patient_IC"],
            "patient_address": payload["patient_address"],
            "patient_number": payload["patient_number"],
            "patient_BOD": payload["patient_BOD"],
        })
        self.save()
        return {"patient_id": patient_id}

    def op_update_patient(self, payload):
        self._require(payload, "patient_id", "patient_name", "patient_IC",
                      "patient_address", "patient_number", "patient_BOD")
        patient = self._must_get_patient(payload["patient_id"].strip())
        for key in ("patient_name", "patient_IC", "patient_address",
                    "patient_number", "patient_BOD"):
            patient[key] = payload[key]
        self.save()
        return {"patient_id": patient["patient_id"]}

    def op_update_patient_contact(self, payload):
        self._require(payload, "patient_id", "patient_address", "patient_number")
        patient = self._must_get_patient(payload["patient_id"].strip())
        patient["patient_address"] = payload["patient_address"]
        patient["patient_number"] = payload["patient_number"]
        self.save()
        return {"patient_id": patient["patient_id"]}

    # -- appointments ------------------------------------------------------
    def op_appointments_for_doctor(self, payload):
        rows = self._filter("Appointments", "doctor_id", payload["doctor_id"])
        return sorted(rows, key=lambda a: str(a.get("appointment_date", "")))

    def op_appointments_for_patient(self, payload):
        rows = self._filter("Appointments", "patient_id", payload["patient_id"])
        return sorted(rows, key=lambda a: str(a.get("appointment_date", "")))

    def op_schedule_appointment(self, payload):
        self._require(payload, "patient_id", "doctor_id", "date", "time")
        patient = self._must_get_patient(payload["patient_id"].strip())
        doctor_id = payload["doctor_id"].strip()
        date = payload["date"].strip()
        time = payload["time"].strip()

        same_day = [a for a in self._filter("Appointments", "doctor_id", doctor_id)
                    if a.get("appointment_date") == date]
        if any(a.get("appointment_time") == time for a in same_day):
            raise ValueError(f"{doctor_id} already has an appointment at {time} on {date}.")

        blocked = self._find("availability", doctor_id=doctor_id, date=date)
        if blocked and blocked.get("status") == "block":
            raise ValueError(f"{doctor_id} is not available on {date}.")

        item = {
            # Same deterministic id as the Lambda; the duplicate check below
            # mirrors its attribute_not_exists(record_id) condition.
            "record_id": f'{patient["patient_id"]}-{date}-{time}',
            "doctor_id": doctor_id,
            "appointment_date": date,
            "appointment_time": time,
            "patient_id": patient["patient_id"],
            "patient_name": patient.get("patient_name", ""),
        }
        if self._find("Appointments", record_id=item["record_id"]):
            raise ValueError(
                f'{patient["patient_id"]} already has an appointment at {time} on {date}.'
            )
        self.data["Appointments"].append(item)
        self.save()
        return item

    # -- receipts ----------------------------------------------------------
    def op_list_receipts(self, _payload):
        return [dict(item) for item in self.data["receipts"]]

    def op_get_receipt(self, payload):
        receipt = self._find("receipts", receipt_id=payload["receipt_id"])
        return dict(receipt) if receipt else None

    def op_receipts_for_patient(self, payload):
        return self._filter("receipts", "patient_id", payload["patient_id"])

    def op_create_receipt(self, payload):
        self._require(payload, "patient_id", "receipt_id", "method", "amount")
        patient = self._must_get_patient(payload["patient_id"].strip())
        receipt_id = payload["receipt_id"].strip()
        if self._find("receipts", receipt_id=receipt_id):
            raise ValueError(f"Receipt ID {receipt_id} already exists.")
        try:
            amount = int(payload["amount"])
        except (TypeError, ValueError):
            raise ValueError("Amount must be a whole number.")
        # int() silently truncates floats from direct JSON calls (12.5 -> 12);
        # mirror the Lambda's explicit rejection so both backends agree.
        if isinstance(payload["amount"], float) and payload["amount"] != amount:
            raise ValueError("Amount must be a whole number.")
        if amount <= 0:
            raise ValueError("Amount must be greater than zero.")
        item = {
            "receipt_id": receipt_id,
            "patient_id": patient["patient_id"],
            "patient_name": patient.get("patient_name", ""),
            "method": payload["method"],
            "amount": amount,
            "date": datetime.now().strftime("%Y/%m/%d"),
        }
        self.data["receipts"].append(item)
        self.save()
        return item

    # -- medical records ---------------------------------------------------
    def op_medical_records(self, payload):
        rows = self._filter("medicalRecord", "patient_id", payload["patient_id"])
        return sorted(rows, key=lambda r: str(r.get("date", "")))

    def op_add_medical_record(self, payload):
        self._require(payload, "patient_id", "diagnosis", "prescriptions", "treatment_plan")
        patient_id = payload["patient_id"].strip()
        self._must_get_patient(patient_id)
        now = datetime.now()
        item = {
            "record_id": f'{patient_id}-{now.strftime("%Y-%m-%d")}-{now.strftime("%H%M%S")}',
            "patient_id": patient_id,
            "diagnosis": payload["diagnosis"],
            "prescriptions": payload["prescriptions"],
            "treatment_plan": payload["treatment_plan"],
            "date": now.strftime("%Y-%m-%d"),
        }
        self.data["medicalRecord"].append(item)
        self.save()
        return item

    def op_delete_medical_records(self, payload):
        patient_id = payload["patient_id"].strip()
        before = len(self.data["medicalRecord"])
        self.data["medicalRecord"] = [
            r for r in self.data["medicalRecord"]
            if str(r.get("patient_id", "")).strip() != patient_id
        ]
        deleted = before - len(self.data["medicalRecord"])
        self.save()
        return {"deleted": deleted}

    # -- availability ------------------------------------------------------
    def op_set_availability(self, payload):
        self._require(payload, "doctor_id", "date", "status")
        status = payload["status"].strip()
        if status not in ("block", "unblock"):
            raise ValueError("Status must be 'block' or 'unblock'.")
        doctor_id = payload["doctor_id"].strip()
        date = payload["date"].strip()
        existing = self._find("availability", doctor_id=doctor_id, date=date)
        if existing:
            existing["status"] = status
        else:
            self.data["availability"].append(
                {"doctor_id": doctor_id, "date": date, "status": status}
            )
        self.save()
        return {"doctor_id": doctor_id, "date": date, "status": status}

    def op_availability_for_doctor(self, payload):
        rows = self._filter("availability", "doctor_id", payload["doctor_id"])
        return sorted(rows, key=lambda r: str(r.get("date", "")))

    # -- nursing -----------------------------------------------------------
    def op_add_observation(self, payload):
        self._require(payload, "patient_id", "blood_pressure", "pulse", "temperature")
        patient = self._must_get_patient(payload["patient_id"].strip())
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
        self.data["observations"].append(item)
        self.save()
        return item

    def op_add_medication(self, payload):
        self._require(payload, "patient_id", "medicine", "dosage", "time_given")
        patient_id = payload["patient_id"].strip()
        self._must_get_patient(patient_id)
        item = {
            "medication_id": f'{patient_id}-{datetime.now().strftime("%Y%m%d%H%M%S")}',
            "patient_id": patient_id,
            "medicine": payload["medicine"],
            "dosage": payload["dosage"],
            "time_given": payload["time_given"],
        }
        self.data["medications"].append(item)
        self.save()
        return item

    # -- AI consultation (stands in for Bedrock) ---------------------------
    def op_consultation(self, payload):
        self._require(payload, "patient_id", "problem")
        patient_id = payload["patient_id"].strip()
        self._must_get_patient(patient_id)  # mirror the Lambda's check
        problem = payload["problem"].strip()
        advice = {
            "fever": ("A mild fever is usually caused by a viral infection. Rest, drink "
                      "plenty of fluids, and use paracetamol as directed on the package. "
                      "See a doctor if it lasts more than 3 days or goes above 39C."),
            "headache": ("Most headaches ease with rest, hydration and a quiet room. "
                         "Seek care immediately if it is the worst headache of your life, "
                         "comes with vomiting, blurred vision or weakness."),
            "cough": ("A cough after a cold usually settles within 2 to 3 weeks. Warm "
                      "fluids and rest help. See a doctor if you cough blood, feel "
                      "breathless, or it lasts beyond 3 weeks."),
            "fatigue": ("Tiredness is often linked to sleep, stress or diet. Improve "
                        "sleep routine first. If it persists for weeks, a blood test at "
                        "the clinic is worthwhile."),
        }
        matched = next((text for keyword, text in advice.items() if keyword in problem.lower()), None)
        body = matched or (
            "General self-care for most mild symptoms: rest, stay hydrated, and "
            "monitor how you feel over the next 24 to 48 hours. If symptoms worsen, "
            "persist beyond a few days, or you develop severe pain, breathing "
            "difficulty or a high fever, please book an appointment."
        )
        return {
            "reply": (
                "Note: this is canned demo guidance standing in for a Bedrock call.\n\n"
                + body
            ),
            "model": "demo-canned-reply",
        }

    # -- routing (mirrors lambda_function.ROUTES) --------------------------
    ROUTES = {
        "login": op_login,
        "patient_login": op_patient_login,
        "ping": lambda self, _p: {"service": "clinic-demo", "patients": len(self.data["patients"])},
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


# ---------------------------------------------------------------------------
# Reusable widgets
# ---------------------------------------------------------------------------
class FormDialog(tk.Toplevel):
    """Modal form generated from a list of field definitions.

    on_submit receives {key: value}. Return an error string to keep the dialog
    open, or None to accept the input.
    """

    def __init__(self, parent, title, fields, submit_label="Submit", on_submit=None):
        super().__init__(parent)
        self.title(title)
        self.resizable(False, False)
        self.transient(parent)
        self.on_submit = on_submit
        self.vars = {}

        body = ttk.Frame(self, padding=16)
        body.pack(fill="both", expand=True)

        for row, field in enumerate(fields):
            ttk.Label(body, text=field["label"]).grid(
                row=row, column=0, sticky="w", pady=4, padx=(0, 14)
            )
            variable = tk.StringVar(value=str(field.get("default", "")))
            self.vars[field["key"]] = variable
            if field.get("options"):
                widget = ttk.Combobox(
                    body, textvariable=variable, values=field["options"],
                    state="readonly", width=30,
                )
            else:
                widget = ttk.Entry(
                    body, textvariable=variable, width=48,
                    show="*" if field.get("secret") else "",
                )
            widget.grid(row=row, column=1, sticky="ew", pady=4)

        buttons = ttk.Frame(body)
        buttons.grid(row=len(fields), column=0, columnspan=2, sticky="e", pady=(18, 0))
        ttk.Button(buttons, text="Cancel", command=self.destroy).pack(side="right", padx=(8, 0))
        ttk.Button(buttons, text=submit_label, command=self.submit).pack(side="right")

        self.bind("<Return>", lambda _event: self.submit())
        self.bind("<Escape>", lambda _event: self.destroy())
        self.update_idletasks()
        parent.update_idletasks()
        x = parent.winfo_rootx() + (parent.winfo_width() - self.winfo_width()) // 2
        y = parent.winfo_rooty() + (parent.winfo_height() - self.winfo_height()) // 3
        self.geometry(f"+{max(x, 0)}+{max(y, 0)}")
        self.grab_set()
        self.focus_force()

    def submit(self):
        values = {key: var.get().strip() for key, var in self.vars.items()}
        if self.on_submit is None:
            self.destroy()
            return
        error = self.on_submit(values)
        if error:
            messagebox.showwarning("Check your input", error, parent=self)
            return
        self.destroy()


class TableWindow(tk.Toplevel):
    def __init__(self, parent, title, columns, rows, note=None):
        super().__init__(parent)
        self.title(title)
        self.geometry("820x440")
        self.transient(parent)

        header = ttk.Frame(self, padding=(16, 14, 16, 0))
        header.pack(fill="x")
        ttk.Label(header, text=title, style="H1.TLabel").pack(anchor="w")
        if note:
            ttk.Label(header, text=note, style="Muted.TLabel").pack(anchor="w", pady=(2, 0))

        if not rows:
            ttk.Label(self, text="No records found.", padding=24).pack(anchor="w")
            ttk.Button(self, text="Close", command=self.destroy).pack(pady=(0, 14))
            return

        body = ttk.Frame(self, padding=16)
        body.pack(fill="both", expand=True)
        tree = ttk.Treeview(
            body, columns=[key for key, _, _ in columns], show="headings", height=13
        )
        for key, heading, width in columns:
            tree.heading(key, text=heading)
            tree.column(key, width=width, anchor="w")
        for row in rows:
            tree.insert("", "end", values=[row.get(key, "") for key, _, _ in columns])

        vertical = ttk.Scrollbar(body, orient="vertical", command=tree.yview)
        horizontal = ttk.Scrollbar(body, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
        tree.grid(row=0, column=0, sticky="nsew")
        vertical.grid(row=0, column=1, sticky="ns")
        horizontal.grid(row=1, column=0, sticky="ew")
        body.rowconfigure(0, weight=1)
        body.columnconfigure(0, weight=1)

        ttk.Button(self, text="Close", command=self.destroy).pack(pady=(0, 14))


def show_text_window(parent, title, text):
    window = tk.Toplevel(parent)
    window.title(title)
    window.geometry("700x480")
    window.transient(parent)

    body = ttk.Frame(window, padding=16)
    body.pack(fill="both", expand=True)
    widget = tk.Text(
        body, wrap="word", font=mono_font(10), relief="solid", borderwidth=1,
        background=FIELD, foreground=TEXT, insertbackground=ACCENT,
        selectbackground=BUTTON_BG, selectforeground="#ffffff",
    )
    widget.insert("1.0", text)
    widget.configure(state="disabled")
    vertical = ttk.Scrollbar(body, orient="vertical", command=widget.yview)
    widget.configure(yscrollcommand=vertical.set)
    widget.pack(side="left", fill="both", expand=True)
    vertical.pack(side="right", fill="y")

    ttk.Button(window, text="Close", command=window.destroy).pack(pady=(0, 14))
    return window


# ---------------------------------------------------------------------------
# Screens
# ---------------------------------------------------------------------------
class LoginFrame(ttk.Frame):
    def __init__(self, master, app):
        super().__init__(master)
        self.app = app

        ttk.Label(self, text="Clinic Management System", style="Title.TLabel").pack(pady=(40, 4))
        ttk.Label(
            self,
            text="Sign in with a role. Staff use username + password, patients use their patient ID + password.",
            style="Muted.TLabel",
        ).pack(pady=(0, 6))
        ttk.Label(
            self,
            text="Accounts live in Amazon Cognito (demo mode: demo_data.json). "
                 "A first-time patient password is changed at first sign-in.",
            style="Muted.TLabel",
            font=font(9),
        ).pack(pady=(0, 18))

        card = ttk.LabelFrame(self, text=" Sign in ", padding=20)
        card.pack()

        self.role = tk.StringVar(value="Receptionist")
        self.source = tk.StringVar()
        self.username = tk.StringVar()
        self.password = tk.StringVar()
        self.patient_id = tk.StringVar()

        ttk.Label(card, text="Data source", style="Card.TLabel").grid(row=0, column=0, sticky="w", pady=6, padx=(0, 14))
        sources = ttk.Combobox(
            card, textvariable=self.source,
            values=["AWS (API Gateway)", "Demo (offline, no AWS)"],
            state="readonly", width=28,
        )
        sources.grid(row=0, column=1, sticky="ew", pady=6)
        sources.bind("<<ComboboxSelected>>", self.on_source_change)

        ttk.Label(card, text="Role", style="Card.TLabel").grid(row=1, column=0, sticky="w", pady=6, padx=(0, 14))
        roles = ttk.Combobox(
            card, textvariable=self.role, values=list(ROLE_LABELS.values()),
            state="readonly", width=28,
        )
        roles.grid(row=1, column=1, sticky="ew", pady=6)
        roles.bind("<<ComboboxSelected>>", self.on_role_change)

        ttk.Label(card, text="Username", style="Card.TLabel").grid(row=2, column=0, sticky="w", pady=6, padx=(0, 14))
        self.username_entry = ttk.Entry(card, textvariable=self.username, width=30)
        self.username_entry.grid(row=2, column=1, sticky="ew", pady=6)

        ttk.Label(card, text="Password", style="Card.TLabel").grid(row=3, column=0, sticky="w", pady=6, padx=(0, 14))
        self.password_entry = ttk.Entry(card, textvariable=self.password, width=30, show="*")
        self.password_entry.grid(row=3, column=1, sticky="ew", pady=6)

        ttk.Label(card, text="Patient ID", style="Card.TLabel").grid(row=4, column=0, sticky="w", pady=6, padx=(0, 14))
        self.patient_entry = ttk.Entry(card, textvariable=self.patient_id, width=30)
        self.patient_entry.grid(row=4, column=1, sticky="ew", pady=6)

        actions = ttk.Frame(card)
        actions.grid(row=5, column=0, columnspan=2, sticky="ew", pady=(18, 0))
        ttk.Button(actions, text="Sign in", command=self.attempt_login).pack(side="left", padx=(0, 10))
        ttk.Button(actions, text="Test connection", command=self.test_connection).pack(side="left", padx=(0, 10))
        ttk.Button(actions, text="Configure endpoint", command=self.configure_endpoint).pack(side="left")
        ttk.Button(actions, text="Exit", command=self.app.destroy).pack(side="right", padx=(10, 0))

        self.source.set("Demo (offline, no AWS)" if app.data_source_mode == "demo" else "AWS (API Gateway)")
        self.on_role_change()
        self.username_entry.focus_set()

    def on_role_change(self, _event=None):
        is_patient = self.role.get() == ROLE_LABELS["4"]
        self.username_entry.configure(state="disabled" if is_patient else "normal")
        # Patients type a password too (Cognito sign-in in AWS mode; ignored
        # by the demo backend, which has no Cognito).
        self.password_entry.configure(state="normal")
        self.patient_entry.configure(state="normal" if is_patient else "disabled")

    def on_source_change(self, _event=None):
        mode = "demo" if self.source.get().startswith("Demo") else "aws"
        self.app.set_data_source(mode)

    def configure_endpoint(self):
        db = self.app.db
        FormDialog(
            self,
            "Configure endpoint",
            [
                {"key": "api_url", "label": "Invoke URL", "default": db.api_url or ""},
                {"key": "api_key", "label": "API key", "default": db.api_key or "", "secret": True},
            ],
            submit_label="Save",
            on_submit=self.save_endpoint,
        )

    def save_endpoint(self, values):
        if not values["api_url"].startswith("https://"):
            return "The invoke URL must start with https://"
        if not values["api_key"]:
            return "The API key is required."
        self.app.db.save_config(values["api_url"], values["api_key"])
        self.app.set_data_source("aws")
        self.source.set("AWS (API Gateway)")
        self.app.set_status(f"Endpoint saved: {self.app.db.endpoint_label}")
        return None

    def test_connection(self):
        self.app.set_status("Testing the connection ...")

        def work():
            result = self.app.db.call("ping")
            return result

        def on_ok(result):
            if self.app.data_source_mode == "demo":
                message = (
                    f"Demo backend answered: {result.get('patients', '?')} patient(s) "
                    "loaded from demo_data.json.\n\n"
                    "No network and no AWS involved. The real path "
                    "(API Gateway -> Lambda -> DynamoDB/Bedrock) is the same code "
                    "with the data source switched to AWS."
                )
            else:
                message = (
                    "The backend answered. All AWS credentials stay in the "
                    "Lambda execution role; this client only holds the API key."
                )
            self.app.set_status(f"Connection OK | {self.app.db.endpoint_label}")
            messagebox.showinfo("Connection OK", message, parent=self)

        self.app.run_async(
            work,
            on_ok,
            self.app.show_error,
        )

    def attempt_login(self):
        role_code = next(
            code for code, label in ROLE_LABELS.items() if label == self.role.get()
        )
        if role_code == "4":
            patient_id = self.patient_id.get().strip()
            if not patient_id:
                messagebox.showwarning("Missing ID", "Enter the patient ID.", parent=self)
                return
            # Read tk variables HERE, on the main thread; worker threads must
            # never touch Tk (StringVar.get() included).
            password = self.password.get()
            self.app.set_status(f"Signing in patient {patient_id} ...")
            self.app.run_async(
                lambda: self.app.db.patient_login(patient_id, password),
                lambda _result: self._after_patient_auth(patient_id),
                self._on_auth_error,
            )
            return

        username = self.username.get().strip()
        if not username or not self.password.get():
            messagebox.showwarning(
                "Missing fields", "Enter both username and password.", parent=self
            )
            return

        # Both modes: accounts live in the backend (AWS: Cognito user pool,
        # demo: demo_data.json). This client holds no credentials.
        password = self.password.get()
        self.app.set_status(f"Signing in as {username} ...")
        self.app.run_async(
            lambda: self.app.db.login(username, password, role_code),
            lambda result: self.app.login_success(
                result["role"], result["display_name"]
            ),
            self._on_auth_error,
        )

    def _after_patient_auth(self, patient_id):
        """Fetch the patient record so the header can show the real name.

        Cognito does not return profile fields, so the just-issued role-4
        token is used for an own-records get_patient (demo mode already
        returns the name from patient_login; the extra read is harmless).
        """
        self.app.run_async(
            lambda: self.app.db.get_patient(patient_id),
            lambda patient: self.finish_patient_login(
                patient_id, patient or {"patient_id": patient_id}
            ),
            self._on_auth_error,
        )

    def _on_auth_error(self, exc):
        if isinstance(exc, NewPasswordRequired) and self.app.data_source_mode == "aws":
            self._prompt_new_password(exc)
        else:
            self.app.show_error(exc)

    def _prompt_new_password(self, pending):
        self.app.set_status("First sign-in: choose a new password.")
        FormDialog(
            self,
            "Choose a new password",
            [
                {"key": "new_password", "label": "New password", "secret": True},
                {"key": "confirm", "label": "Repeat new password", "secret": True},
            ],
            submit_label="Save and sign in",
            on_submit=lambda values: self._submit_new_password(pending, values),
        )

    def _submit_new_password(self, pending, values):
        new_password = values["new_password"]
        if not new_password:
            return "Enter a new password."
        if len(new_password) < 6:
            return "The password must be at least 6 characters."
        if new_password != values["confirm"]:
            return "The two passwords do not match."
        self.app.run_async(
            lambda: self.app.db.complete_new_password(
                pending.username, new_password, pending.session
            ),
            lambda result: self.app.login_success(
                result["role"], result["display_name"],
                patient_id=pending.username if result["role"] == "4" else None,
            ),
            self._on_auth_error,
        )
        return None

    def finish_patient_login(self, patient_id, patient):
        if not patient:
            messagebox.showerror("Not found", f"No patient with ID {patient_id}.", parent=self)
            return
        self.app.login_success("4", patient.get("patient_name", patient_id), patient_id=patient_id)


class HomeFrame(ttk.Frame):
    def __init__(self, master, app, title, subtitle, actions):
        super().__init__(master)

        header = ttk.Frame(self)
        header.pack(fill="x")
        ttk.Label(header, text=title, style="H1.TLabel").pack(side="left")
        ttk.Button(header, text="Log out", command=app.show_login).pack(side="right")
        ttk.Label(self, text=subtitle, style="Muted.TLabel", wraplength=880,
                  justify="left").pack(anchor="w", pady=(4, 16))

        grid = ttk.Frame(self)
        grid.pack(fill="both", expand=True)
        grid.columnconfigure(0, weight=1)
        grid.columnconfigure(1, weight=1)

        for index, (label, description, handler) in enumerate(actions):
            cell = ttk.Frame(grid, padding=6)
            cell.grid(row=index // 2, column=index % 2, sticky="nsew")
            ttk.Button(cell, text=label, width=36, command=handler).pack(anchor="w")
            ttk.Label(
                cell, text=description, style="Muted.TLabel", wraplength=400,
                justify="left",
            ).pack(anchor="w", pady=(4, 0))


# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------
class ClinicApp(tk.Tk):
    def __init__(self):
        super().__init__()
        apply_theme(self)
        self.title("Clinic Management System (serverless)")
        self.minsize(920, 620)
        try:
            self.state("zoomed")  # start maximized (Windows)
        except tk.TclError:
            self.geometry("1020x700")

        tkfont.nametofont("TkDefaultFont").configure(size=10)

        self.db = None
        self.current_role = None
        self.patient_id = None
        self._task_queue = queue.Queue()
        self._results = queue.Queue()
        self._pending = 0
        self.data_source_mode = self.read_mode()
        self.db = self.make_backend(self.data_source_mode)

        self.container = ttk.Frame(self, padding=20)
        self.container.pack(fill="both", expand=True)

        self.status_var = tk.StringVar()
        ttk.Label(
            self, textvariable=self.status_var, anchor="w", style="Status.TLabel"
        ).pack(fill="x", side="bottom")

        self.show_login()

    # -- plumbing ----------------------------------------------------------
    def read_mode(self):
        # AWS is the primary path; demo is something you opt into.
        if CONFIG_FILE.exists():
            try:
                return json.loads(CONFIG_FILE.read_text(encoding="utf-8")).get("mode", "aws")
            except json.JSONDecodeError:
                pass
        return "aws"

    def make_backend(self, mode):
        return ApiClient() if mode == "aws" else DemoBackend()

    def set_data_source(self, mode):
        if mode == self.data_source_mode:
            return
        self.data_source_mode = mode
        self.db = self.make_backend(mode)
        config = {}
        if CONFIG_FILE.exists():
            try:
                config = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                pass
        config["mode"] = mode
        CONFIG_FILE.write_text(json.dumps(config, indent=2), encoding="utf-8")
        self.set_status(f"Data source: {self.db.endpoint_label}")

    def set_status(self, text):
        self.status_var.set(text)

    def swap(self, frame_class, **kwargs):
        for child in self.container.winfo_children():
            child.destroy()
        frame_class(self.container, self, **kwargs).pack(fill="both", expand=True)

    def run_async(self, work, on_success, on_error=None):
        """Run a network call off the UI thread without freezing the window.

        Worker threads never touch Tk: they only push a result onto a queue,
        and a poller running on the main thread picks it up. Calling
        Tk.after() from a worker thread is not thread-safe and fails outright
        when no main loop is running (for example in tests).
        """
        self._task_queue.put((on_success, on_error or self.show_error, work))
        self._pending += 1
        threading.Thread(target=self._run_task, daemon=True).start()
        if self._pending == 1:
            self.after(40, self._drain_tasks)

    def _run_task(self):
        on_success, on_error, work = self._task_queue.get()
        try:
            result = work()
        except Exception as exc:  # surfaced instead of swallowed
            self._results.put((on_error, exc))
        else:
            self._results.put((on_success, result))

    def _drain_tasks(self):
        while not self._results.empty():
            callback, value = self._results.get()
            self._pending -= 1
            try:
                callback(value)
            except Exception:
                # A broken callback must not kill the pump: results still in
                # the queue need delivery, and future run_async calls rely on
                # this reschedule below to ever get a drainer again.
                traceback.print_exc()
        if self._pending > 0:
            self.after(40, self._drain_tasks)

    def show_error(self, exc):
        self.set_status(f"Failed: {exc}".splitlines()[0])
        messagebox.showerror("Operation failed", describe_error(exc), parent=self)

    def show_login(self):
        self.current_role = None
        self.patient_id = None
        source_label = "demo (offline)" if self.data_source_mode == "demo" else "AWS (API Gateway)"
        self.set_status(f"Data source: {source_label} | {self.db.endpoint_label}")
        self.swap(LoginFrame)

    def login_success(self, role_code, display_name, patient_id=None):
        self.current_role = role_code
        self.patient_id = patient_id
        self.display_name = display_name
        label = ROLE_LABELS[role_code]
        self.set_status(f"Signed in as {display_name} ({label}) | {self.db.endpoint_label}")
        if role_code == "1":
            self.show_receptionist_home(display_name)
        elif role_code == "2":
            self.show_doctor_home(display_name)
        elif role_code == "3":
            self.show_nurse_home(display_name)
        else:
            self.show_patient_home(display_name)

    # -- role homes --------------------------------------------------------
    def show_receptionist_home(self, name):
        self.swap(
            HomeFrame,
            title="Reception",
            subtitle=f"Welcome, {name}. Registration, appointments, payments and receipts.",
            actions=[
                ("Register new patient", "Create a row in the patients table.", self.action_register_patient),
                ("Update patient detail", "Edit name, IC, address, contact and date of birth.", self.action_update_patient),
                ("Schedule appointment", "Books a doctor slot after checking clashes and blocked dates.", self.action_schedule_appointment),
                ("Process payment", "Writes a receipt and shows the summary.", self.action_payment),
                ("Generate receipt", "Look up an existing receipt by ID.", self.action_generate_receipt),
                ("Browse patients", "List every row in the patients table.", self.action_browse_patients),
                ("Browse receipts", "List every receipt issued so far.", self.action_browse_receipts),
            ],
        )

    def show_doctor_home(self, name):
        self.swap(
            HomeFrame,
            title="Doctor",
            subtitle=f"Welcome, {name}. Clinical records, appointments and availability.",
            actions=[
                ("Update patient record", "Append a diagnosis, prescription and treatment plan.", self.action_add_medical_record),
                ("View medical history", "Every record belonging to one patient.", self.action_view_medical_history),
                ("Delete medical record", "Remove all records belonging to one patient.", self.action_delete_medical_record),
                ("View appointments", "Appointments booked for one doctor.", self.action_view_appointments_doctor),
                ("Set availability", "Block or unblock a specific date.", self.action_set_availability),
                ("View availability", "Blocked and unblocked dates for one doctor.", self.action_view_availability),
            ],
        )

    def show_nurse_home(self, name):
        self.swap(
            HomeFrame,
            title="Nurse",
            subtitle=f"Welcome, {name}. Ward duties and medication logging.",
            actions=[
                ("View doctor's appointment list", "Appointments booked for one doctor.", self.action_view_appointments_nurse),
                ("Record patient's observations", "Blood pressure, pulse and temperature.", self.action_add_observation),
                ("View doctor's prescriptions", "Prescriptions recorded for one patient.", self.action_view_prescriptions),
                ("Administer medicine", "Log medicine, dosage and time given.", self.action_administer_medicine),
            ],
        )

    def show_patient_home(self, name):
        self.swap(
            HomeFrame,
            title="Patient",
            subtitle=f"Welcome, {name}. Your ID is {self.patient_id}.",
            actions=[
                ("View medical records", "Your diagnosis, prescriptions and treatment plan.", self.action_view_own_records),
                ("Consultation", "Ask the AI assistant about a symptom.", self.action_consultation),
                ("Schedule appointment", "Book a slot with a doctor.", self.action_schedule_appointment),
                ("View my appointments", "Appointments booked under your ID.", self.action_view_own_appointments),
                ("View payment history", "Receipts issued under your ID.", self.action_view_own_payments),
                ("Update my contact info", "Change the address and phone number on file.", self.action_update_own_contact),
            ],
        )

    # -- shared actions ----------------------------------------------------
    def action_register_patient(self):
        FormDialog(
            self,
            "Register new patient",
            [
                {"key": "patient_id", "label": "Patient ID (BXX)"},
                {"key": "patient_name", "label": "Name"},
                {"key": "patient_IC", "label": "IC number"},
                {"key": "patient_address", "label": "Address"},
                {"key": "patient_number", "label": "Contact number"},
                {"key": "patient_BOD", "label": "Date of birth (YYYY/MM/DD)"},
            ],
            submit_label="Register",
            on_submit=self.submit_register,
        )

    def submit_register(self, values):
        if not all(values.values()):
            return "Every field is required."

        def registered(result):
            self.set_status(f"Patient {values['patient_id']} registered")
            temporary_password = (result or {}).get("temporary_password")
            if temporary_password:
                message = (
                    f"Patient {values['patient_id']} was added.\n\n"
                    f"Cognito sign-in (AWS mode):\n"
                    f"  Username: {values['patient_id']}\n"
                    f"  Temporary password: {temporary_password}\n\n"
                    "Hand it to the patient; they must choose a new "
                    "password at first sign-in."
                )
            else:
                message = (
                    f"Patient {values['patient_id']} was added.\n\n"
                    "Demo mode: the patient signs in with their ID only."
                )
            messagebox.showinfo("Registered", message, parent=self)

        self.run_async(
            lambda: self.db.create_patient(values),
            registered,
            self.show_error,
        )
        return None

    def action_update_patient(self):
        FormDialog(
            self,
            "Update patient detail",
            [{"key": "patient_id", "label": "Patient ID"}],
            submit_label="Load",
            on_submit=self.load_patient_for_update,
        )

    def load_patient_for_update(self, values):
        patient_id = values["patient_id"]
        if not patient_id:
            return "Enter the patient ID."
        self.run_async(
            lambda: self.db.get_patient(patient_id),
            lambda patient: self.open_update_patient_form(patient_id, patient),
            self.show_error,
        )
        return None

    def open_update_patient_form(self, patient_id, patient):
        if not patient:
            messagebox.showerror("Not found", f"No patient with ID {patient_id}.", parent=self)
            return
        FormDialog(
            self,
            f"Update {patient_id}",
            [
                {"key": "patient_name", "label": "Name", "default": patient.get("patient_name", "")},
                {"key": "patient_IC", "label": "IC number", "default": patient.get("patient_IC", "")},
                {"key": "patient_address", "label": "Address", "default": patient.get("patient_address", "")},
                {"key": "patient_number", "label": "Contact number", "default": patient.get("patient_number", "")},
                {"key": "patient_BOD", "label": "Date of birth", "default": patient.get("patient_BOD", "")},
            ],
            submit_label="Save",
            on_submit=lambda values: self.submit_update_patient(patient_id, values),
        )

    def submit_update_patient(self, patient_id, values):
        if not all(values.values()):
            return "Every field is required."
        self.run_async(
            lambda: self.db.update_patient(patient_id, values),
            lambda _result: (
                self.set_status(f"Patient {patient_id} updated"),
                messagebox.showinfo("Updated", f"Patient {patient_id} was updated.", parent=self),
            ),
            self.show_error,
        )
        return None

    def action_schedule_appointment(self):
        if self.app.current_role == "4":
            # Patients book for themselves only; the backend enforces this
            # against the session token, so skip the patient picker.
            self.open_schedule_form(
                [{"patient_id": self.app.patient_id,
                  "patient_name": self.app.display_name}]
            )
            return
        self.run_async(self.db.list_patients, self.open_schedule_form, self.show_error)

    def open_schedule_form(self, patients):
        if not patients:
            messagebox.showinfo("No patients", "Register a patient before booking.", parent=self)
            return
        options = [f"{p['patient_id']} | {p.get('patient_name', '')}" for p in patients]
        FormDialog(
            self,
            "Schedule appointment",
            [
                {"key": "patient", "label": "Patient", "options": options, "default": options[0]},
                {"key": "doctor_id", "label": "Doctor ID"},
                {"key": "date", "label": "Date (YYYY/MM/DD)"},
                {"key": "time", "label": "Start time (HH:MM)"},
            ],
            submit_label="Schedule",
            on_submit=self.submit_schedule,
        )

    def submit_schedule(self, values):
        if not values["doctor_id"] or not values["date"] or not values["time"]:
            return "Doctor ID, date and time are required."
        patient_id = values["patient"].split(" | ")[0].strip()
        self.run_async(
            lambda: self.db.schedule_appointment(
                values["doctor_id"], values["date"], values["time"], patient_id
            ),
            lambda item: (
                self.set_status(
                    f"Appointment for {item['patient_name']} with {item['doctor_id']} on {item['appointment_date']}"
                ),
                messagebox.showinfo(
                    "Scheduled",
                    f"{item['patient_name']} is booked with {item['doctor_id']} "
                    f"on {item['appointment_date']} at {item['appointment_time']}.",
                    parent=self,
                ),
            ),
            self.show_error,
        )
        return None

    # -- receptionist ------------------------------------------------------
    def action_browse_patients(self):
        self.run_async(
            self.db.list_patients,
            lambda patients: TableWindow(
                self,
                "Patients",
                [
                    ("patient_id", "Patient ID", 110),
                    ("patient_name", "Name", 170),
                    ("patient_IC", "IC", 130),
                    ("patient_address", "Address", 200),
                    ("patient_number", "Contact", 120),
                    ("patient_BOD", "Date of birth", 120),
                ],
                patients,
                note=f"{len(patients)} patient(s)",
            ),
            self.show_error,
        )

    def action_browse_receipts(self):
        self.run_async(
            self.db.list_receipts,
            lambda receipts: TableWindow(
                self,
                "Receipts",
                [
                    ("receipt_id", "Receipt ID", 100),
                    ("patient_id", "Patient ID", 100),
                    ("patient_name", "Name", 170),
                    ("method", "Method", 90),
                    ("amount", "Amount (RM)", 100),
                    ("date", "Date", 110),
                ],
                receipts,
                note=f"{len(receipts)} receipt(s)",
            ),
            self.show_error,
        )

    def action_payment(self):
        FormDialog(
            self,
            "Process payment",
            [{"key": "patient_id", "label": "Patient ID"}],
            submit_label="Load",
            on_submit=self.load_patient_for_payment,
        )

    def load_patient_for_payment(self, values):
        patient_id = values["patient_id"]
        if not patient_id:
            return "Enter the patient ID."
        self.run_async(
            lambda: self.db.get_patient(patient_id),
            lambda patient: self.open_payment_form(patient_id, patient),
            self.show_error,
        )
        return None

    def open_payment_form(self, patient_id, patient):
        if not patient:
            messagebox.showerror("Not found", f"No patient with ID {patient_id}.", parent=self)
            return
        FormDialog(
            self,
            f"Payment for {patient.get('patient_name', patient_id)}",
            [
                {"key": "receipt_id", "label": "Receipt ID (RXX)"},
                {"key": "method", "label": "Payment method", "options": ["Bank", "Cash"], "default": "Cash"},
                {"key": "amount", "label": "Amount (RM)"},
            ],
            submit_label="Process payment",
            on_submit=lambda values: self.submit_payment(patient, values),
        )

    def submit_payment(self, patient, values):
        if not values["receipt_id"]:
            return "Receipt ID is required."
        try:
            amount = int(values["amount"])
        except ValueError:
            return "Amount must be a whole number."
        if amount <= 0:
            return "Amount must be greater than zero."
        self.run_async(
            lambda: self.db.create_receipt(values["receipt_id"], patient, values["method"], amount),
            lambda receipt: (
                self.set_status(f"Receipt {receipt['receipt_id']} issued"),
                show_text_window(self, f"Receipt {receipt['receipt_id']}", receipt_text(receipt, patient)),
            ),
            self.show_error,
        )
        return None

    def action_generate_receipt(self):
        FormDialog(
            self,
            "Generate receipt",
            [{"key": "receipt_id", "label": "Receipt ID"}],
            submit_label="Generate",
            on_submit=self.load_receipt,
        )

    def load_receipt(self, values):
        receipt_id = values["receipt_id"]
        if not receipt_id:
            return "Enter the receipt ID."

        def work():
            receipt = self.db.get_receipt(receipt_id)
            if not receipt:
                raise ValueError(f"Receipt {receipt_id} was not found.")
            patient = self.db.get_patient(receipt["patient_id"])
            if not patient:
                raise ValueError(f"Patient {receipt['patient_id']} was not found.")
            return receipt, patient

        self.run_async(
            work,
            lambda pair: show_text_window(self, f"Receipt {receipt_id}", receipt_text(pair[0], pair[1])),
            self.show_error,
        )
        return None

    # -- doctor ------------------------------------------------------------
    def action_add_medical_record(self):
        FormDialog(
            self,
            "Update patient record",
            [
                {"key": "patient_id", "label": "Patient ID"},
                {"key": "diagnosis", "label": "Diagnosis"},
                {"key": "prescriptions", "label": "Prescriptions"},
                {"key": "treatment_plan", "label": "Treatment plan"},
            ],
            submit_label="Save record",
            on_submit=self.submit_medical_record,
        )

    def submit_medical_record(self, values):
        if not all(values.values()):
            return "Every field is required."
        self.run_async(
            lambda: self.db.add_medical_record(
                values["patient_id"],
                values["diagnosis"],
                values["prescriptions"],
                values["treatment_plan"],
            ),
            lambda record: (
                self.set_status(f"Record added for {record['patient_id']}"),
                messagebox.showinfo(
                    "Record saved",
                    f"A new record for {record['patient_id']} was added on {record['date']}.",
                    parent=self,
                ),
            ),
            self.show_error,
        )
        return None

    def action_view_medical_history(self):
        FormDialog(
            self,
            "View medical history",
            [{"key": "patient_id", "label": "Patient ID"}],
            submit_label="View",
            on_submit=lambda values: self.show_records(values.get("patient_id", ""), "Medical history"),
        )

    def show_records(self, patient_id, title):
        if not patient_id:
            return "Enter the patient ID."
        self.run_async(
            lambda: self.db.medical_records(patient_id),
            lambda records: TableWindow(
                self,
                f"{title}: {patient_id}",
                [
                    ("date", "Date", 110),
                    ("diagnosis", "Diagnosis", 180),
                    ("prescriptions", "Prescriptions", 200),
                    ("treatment_plan", "Treatment plan", 200),
                ],
                records,
                note=f"{len(records)} record(s)",
            ),
            self.show_error,
        )
        return None

    def action_delete_medical_record(self):
        FormDialog(
            self,
            "Delete medical record",
            [{"key": "patient_id", "label": "Patient ID"}],
            submit_label="Delete all",
            on_submit=self.confirm_delete_records,
        )

    def confirm_delete_records(self, values):
        patient_id = values["patient_id"]
        if not patient_id:
            return "Enter the patient ID."
        if not messagebox.askyesno(
            "Confirm deletion",
            f"Delete every medical record of patient {patient_id}? This cannot be undone.",
            parent=self,
        ):
            return None
        self.run_async(
            lambda: self.db.delete_medical_records(patient_id),
            lambda count: (
                self.set_status(f"{count} record(s) deleted for {patient_id}"),
                messagebox.showinfo("Deleted", f"{count} record(s) removed for {patient_id}.", parent=self),
            ),
            self.show_error,
        )
        return None

    def action_view_appointments_doctor(self):
        FormDialog(
            self,
            "View appointments",
            [{"key": "doctor_id", "label": "Doctor ID"}],
            submit_label="View",
            on_submit=lambda values: self.show_doctor_appointments(values.get("doctor_id", "")),
        )

    def show_doctor_appointments(self, doctor_id):
        if not doctor_id:
            return "Enter the doctor ID."
        self.run_async(
            lambda: self.db.appointments_for_doctor(doctor_id),
            lambda appointments: TableWindow(
                self,
                f"Appointments for {doctor_id}",
                [
                    ("appointment_date", "Date", 110),
                    ("appointment_time", "Time", 90),
                    ("patient_id", "Patient ID", 110),
                    ("patient_name", "Patient name", 200),
                ],
                sorted(appointments, key=lambda a: str(a.get("appointment_date", ""))),
                note=f"{len(appointments)} appointment(s)",
            ),
            self.show_error,
        )
        return None

    def action_set_availability(self):
        FormDialog(
            self,
            "Set availability",
            [
                {"key": "doctor_id", "label": "Doctor ID"},
                {"key": "date", "label": "Date (YYYY/MM/DD)"},
                {"key": "status", "label": "Status", "options": ["block", "unblock"], "default": "block"},
            ],
            submit_label="Save",
            on_submit=self.submit_availability,
        )

    def submit_availability(self, values):
        if not values["doctor_id"] or not values["date"]:
            return "Doctor ID and date are required."
        self.run_async(
            lambda: self.db.set_availability(values["doctor_id"], values["date"], values["status"]),
            lambda _result: (
                self.set_status(f"{values['doctor_id']} {values['status']}ed on {values['date']}"),
                messagebox.showinfo(
                    "Availability saved",
                    f"{values['doctor_id']} is now '{values['status']}' on {values['date']}.",
                    parent=self,
                ),
            ),
            self.show_error,
        )
        return None

    def action_view_availability(self):
        FormDialog(
            self,
            "View availability",
            [{"key": "doctor_id", "label": "Doctor ID"}],
            submit_label="View",
            on_submit=lambda values: self.show_availability(values.get("doctor_id", "")),
        )

    def show_availability(self, doctor_id):
        if not doctor_id:
            return "Enter the doctor ID."
        self.run_async(
            lambda: self.db.availability_for_doctor(doctor_id),
            lambda rows: TableWindow(
                self,
                f"Availability for {doctor_id}",
                [("date", "Date", 140), ("status", "Status", 140)],
                sorted(rows, key=lambda r: str(r.get("date", ""))),
                note=f"{len(rows)} entr(y/ies)",
            ),
            self.show_error,
        )
        return None

    # -- nurse -------------------------------------------------------------
    def action_view_appointments_nurse(self):
        FormDialog(
            self,
            "Doctor's appointment list",
            [{"key": "doctor_id", "label": "Doctor ID"}],
            submit_label="View",
            on_submit=lambda values: self.show_doctor_appointments(values.get("doctor_id", "")),
        )

    def action_add_observation(self):
        FormDialog(
            self,
            "Record patient's observations",
            [
                {"key": "patient_id", "label": "Patient ID"},
                {"key": "blood_pressure", "label": "Blood pressure"},
                {"key": "pulse", "label": "Pulse"},
                {"key": "temperature", "label": "Temperature"},
            ],
            submit_label="Save observation",
            on_submit=self.submit_observation,
        )

    def submit_observation(self, values):
        if not all(values.values()):
            return "Every field is required."
        self.run_async(
            lambda: self.db.add_observation(
                values["patient_id"],
                values["blood_pressure"],
                values["pulse"],
                values["temperature"],
            ),
            self.show_observation_summary,
            self.show_error,
        )
        return None

    def show_observation_summary(self, item):
        summary = (
            "***** Patient observations *****\n"
            f"Patient ID: {item['patient_id']}\n"
            f"Name: {item['patient_name']}\n"
            f"Blood pressure: {item['blood_pressure']}\n"
            f"Pulse: {item['pulse']}\n"
            f"Temperature: {item['temperature']}\n"
        )
        self.set_status(f"Observation recorded for {item['patient_id']}")
        show_text_window(self, "Observation recorded", summary)

    def action_view_prescriptions(self):
        FormDialog(
            self,
            "View doctor's prescriptions",
            [{"key": "patient_id", "label": "Patient ID"}],
            submit_label="View",
            on_submit=lambda values: self.show_records(values.get("patient_id", ""), "Prescriptions"),
        )

    def action_administer_medicine(self):
        FormDialog(
            self,
            "Administer medicine",
            [
                {"key": "patient_id", "label": "Patient ID"},
                {"key": "medicine", "label": "Medicine name"},
                {"key": "dosage", "label": "Dosage"},
                {"key": "time_given", "label": "Time given"},
            ],
            submit_label="Save record",
            on_submit=self.submit_medication,
        )

    def submit_medication(self, values):
        if not all(values.values()):
            return "Every field is required."
        self.run_async(
            lambda: self.db.add_medication(
                values["patient_id"], values["medicine"], values["dosage"], values["time_given"]
            ),
            lambda item: (
                self.set_status(f"Medicine recorded for {item['patient_id']}"),
                messagebox.showinfo(
                    "Medicine administered",
                    f"Patient ID: {item['patient_id']}\n"
                    f"Medicine: {item['medicine']}\n"
                    f"Dosage: {item['dosage']}\n"
                    f"Time given: {item['time_given']}",
                    parent=self,
                ),
            ),
            self.show_error,
        )
        return None

    # -- patient -----------------------------------------------------------
    def action_view_own_records(self):
        self.show_records(self.patient_id, "My medical records")

    def action_view_own_appointments(self):
        self.run_async(
            lambda: self.db.appointments_for_patient(self.patient_id),
            lambda appointments: TableWindow(
                self,
                "My appointments",
                [
                    ("appointment_date", "Date", 110),
                    ("appointment_time", "Time", 90),
                    ("doctor_id", "Doctor ID", 120),
                ],
                sorted(appointments, key=lambda a: str(a.get("appointment_date", ""))),
                note=f"{len(appointments)} appointment(s)",
            ),
            self.show_error,
        )

    def action_view_own_payments(self):
        self.run_async(
            lambda: self.db.receipts_for_patient(self.patient_id),
            lambda receipts: TableWindow(
                self,
                "My payment history",
                [
                    ("receipt_id", "Receipt ID", 110),
                    ("method", "Method", 100),
                    ("amount", "Amount (RM)", 110),
                    ("date", "Date", 130),
                ],
                receipts,
                note=f"{len(receipts)} receipt(s)",
            ),
            self.show_error,
        )

    def action_update_own_contact(self):
        self.run_async(
            lambda: self.db.get_patient(self.patient_id),
            self.open_contact_form,
            self.show_error,
        )

    def open_contact_form(self, patient):
        if not patient:
            messagebox.showerror("Not found", f"Patient {self.patient_id} was not found.", parent=self)
            return
        FormDialog(
            self,
            "Update my contact info",
            [
                {"key": "patient_address", "label": "Address", "default": patient.get("patient_address", "")},
                {"key": "patient_number", "label": "Contact number", "default": patient.get("patient_number", "")},
            ],
            submit_label="Save",
            on_submit=self.submit_contact,
        )

    def submit_contact(self, values):
        if not all(values.values()):
            return "Both fields are required."
        self.run_async(
            lambda: self.db.update_patient_contact(
                self.patient_id, values["patient_address"], values["patient_number"]
            ),
            lambda _result: (
                self.set_status("Contact information updated"),
                messagebox.showinfo("Updated", "Your contact information was updated.", parent=self),
            ),
            self.show_error,
        )
        return None

    def action_consultation(self):
        FormDialog(
            self,
            "Consultation",
            [
                {"key": "patient_id", "label": "Patient ID", "default": self.patient_id or ""},
                {"key": "problem", "label": "Describe the problem"},
            ],
            submit_label="Ask the assistant",
            on_submit=self.submit_consultation,
        )

    def submit_consultation(self, values):
        if not values["patient_id"] or not values["problem"]:
            return "Patient ID and problem description are required."
        self.set_status("Asking the AI assistant, this can take a few seconds ...")
        self.run_async(
            lambda: self.db.request_consultation(values["patient_id"], values["problem"]),
            self.show_consultation_result,
            self.show_error,
        )
        return None

    def show_consultation_result(self, result):
        self.set_status("Consultation finished")
        reply = result.get("reply") if isinstance(result, dict) else None
        show_text_window(
            self,
            "Consultation result",
            reply if reply else json.dumps(result, indent=2, ensure_ascii=False),
        )


def main():
    ClinicApp().mainloop()


if __name__ == "__main__":
    main()
