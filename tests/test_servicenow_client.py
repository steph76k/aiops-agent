import base64
import json
import unittest

import httpx

from src.servicenow import ServiceNowClient, Settings, SnowAmbiguousWrite, SnowError


KEY = "aiops:2118afc8-9ffd-5aa4-945d-a07dbe65b08e"
SYS_ID = "0123456789abcdef0123456789abcdef"


def record(**overrides):
    return {"sys_id": SYS_ID, "number": "INC0012345", "active": "true", "state": "1",
            "correlation_id": KEY, **overrides}


def settings(**overrides):
    return Settings(instance_url="https://test.service-now.com", user="test-user",
                    password="test-password", dry_run=False, **overrides)


class SettingsTests(unittest.TestCase):
    def test_configuration_and_secret_repr(self):
        value = Settings.from_env({"SERVICENOW_INSTANCE_URL": "https://test.service-now.com/",
            "SERVICENOW_USER": "secret-user", "SERVICENOW_PASSWORD": "secret-password",
            "SERVICENOW_CORRELATION_FIELD": "u_aiops_key", "SERVICENOW_CATEGORY": "software",
            "SERVICENOW_SUBCATEGORY": "application", "SERVICENOW_ASSIGNMENT_GROUP": SYS_ID})
        self.assertTrue(value.enabled)
        self.assertTrue(value.dry_run)
        self.assertEqual(value.instance_url, "https://test.service-now.com")
        self.assertEqual(value.correlation_field, "u_aiops_key")
        self.assertEqual(value.category, "software")
        self.assertEqual(value.subcategory, "application")
        self.assertEqual(value.assignment_group, SYS_ID)
        self.assertNotIn("secret-user", repr(value))
        self.assertNotIn("secret-password", repr(value))
        self.assertFalse(Settings.from_env({}).enabled)
        self.assertFalse(Settings.from_env({"SERVICENOW_DRY_RUN": "false"}).dry_run)
        with self.assertRaises(SnowError):
            Settings.from_env({"SERVICENOW_DRY_RUN": "flase"})

    def test_rejects_unsafe_urls_and_query_fields(self):
        for url in ("http://test.service-now.com", "https://user:secret@test.service-now.com",
                    "https://test.service-now.com?secret=abc", "https://test.service-now.com#secret",
                    "https://test.service-now.com/api/now", "https://", "https://test:invalid",
                    "https://test\\@evil.test", "https://test.service-now.com?",
                    "https://test.service-now.com/#"):
            with self.subTest(url=url), self.assertRaises(SnowError) as caught:
                Settings(instance_url=url)
            self.assertNotIn(url, str(caught.exception))
        for name in ("correlation_id^ORactive", "sys_id", "number", "active", "state",
                     "incident.correlation_id", "", "correlation_id=foo"):
            with self.subTest(field=name), self.assertRaises(SnowError):
                Settings(correlation_field=name)


class ClientTests(unittest.IsolatedAsyncioTestCase):
    async def test_crud_auth_and_exact_query(self):
        calls = []

        def handler(request):
            calls.append(request)
            expected = base64.b64encode(b"test-user:test-password").decode()
            self.assertEqual(request.headers["Authorization"], f"Basic {expected}")
            self.assertEqual(request.url.params["sysparm_fields"],
                             "sys_id,number,active,state,correlation_id")
            self.assertEqual(request.url.params["sysparm_display_value"], "false")
            self.assertEqual(request.extensions["timeout"]["connect"], 5.0)
            self.assertEqual(request.extensions["timeout"]["read"], 30.0)
            if request.method == "GET" and not request.url.path.endswith(SYS_ID):
                self.assertEqual(request.url.params["sysparm_query"], f"correlation_id={KEY}")
                self.assertEqual(request.url.params["sysparm_limit"], "2")
                return httpx.Response(200, json={"result": [record()]})
            return httpx.Response(201 if request.method == "POST" else 200, json={"result": record()})

        async with ServiceNowClient(settings(), transport=httpx.MockTransport(handler)) as client:
            self.assertEqual((await client.find_incident(KEY))["sys_id"], SYS_ID)
            self.assertEqual((await client.get_incident(SYS_ID))["sys_id"], SYS_ID)
            self.assertEqual((await client.create_incident({"correlation_id": KEY,
                                                          "short_description": "RCA"}))["sys_id"], SYS_ID)
            self.assertEqual((await client.update_incident(SYS_ID, {"work_notes": "new evidence"}))["sys_id"], SYS_ID)
        self.assertEqual([request.method for request in calls], ["GET", "GET", "POST", "PATCH"])
        self.assertEqual(json.loads(calls[-1].content), {"work_notes": "new evidence"})

    async def test_custom_field_and_no_match(self):
        responses = [[], [{**record(), "u_aiops_key": KEY}]]

        def handler(request):
            self.assertEqual(request.url.params["sysparm_query"], f"u_aiops_key={KEY}")
            return httpx.Response(200, json={"result": responses.pop(0)})

        async with ServiceNowClient(settings(correlation_field="u_aiops_key"),
                                    transport=httpx.MockTransport(handler)) as client:
            self.assertIsNone(await client.find_incident(KEY))
            self.assertEqual((await client.find_incident(KEY))["u_aiops_key"], KEY)

    async def test_lookup_fails_closed_for_bad_or_ambiguous_results(self):
        missing_field = record()
        missing_field.pop("correlation_id")
        for result in ([record(), record()], [missing_field],
                       [record(correlation_id="aiops:00000000-0000-0000-0000-000000000000")],
                       [record(sys_id="bad")], [record(number="")], [record(active=None)], {}, None):
            with self.subTest(result=result):
                transport = httpx.MockTransport(lambda request: httpx.Response(200, json={"result": result}))
                async with ServiceNowClient(settings(), transport=transport) as client:
                    with self.assertRaises(SnowError):
                        await client.find_incident(KEY)

    async def test_input_validation_prevents_requests(self):
        def handler(request):
            self.fail("Invalid input must not make an HTTP request")

        async with ServiceNowClient(settings(), transport=httpx.MockTransport(handler)) as client:
            for value in ("", "alertmanager:abc", f"{KEY}^ORactive=true", "aiops:ABC", KEY.upper()):
                with self.subTest(correlation=value), self.assertRaises(SnowError):
                    await client.find_incident(value)
            for value in ("", "a/b", f"{SYS_ID}?key=secret", SYS_ID.upper()):
                with self.subTest(sys_id=value), self.assertRaises(SnowError):
                    await client.get_incident(value)
            with self.assertRaises(SnowError):
                await client.create_incident({"short_description": "missing key"})
            with self.assertRaises(SnowError):
                await client.create_incident({"correlation_id": KEY, "sys_id": SYS_ID})
            with self.assertRaises(SnowError):
                await client.update_incident(SYS_ID, {"sys_id": SYS_ID})

    async def test_dry_run_refuses_writes_without_contacting_server(self):
        def handler(request):
            self.fail("Dry-run writes must not make an HTTP request")

        config = Settings(instance_url="https://test.service-now.com", user="test-user", password="test-password")
        async with ServiceNowClient(config, transport=httpx.MockTransport(handler)) as client:
            with self.assertRaisesRegex(SnowError, "dry-run"):
                await client.create_incident({"correlation_id": KEY})
            with self.assertRaisesRegex(SnowError, "dry-run"):
                await client.update_incident(SYS_ID, {"work_notes": "message"})

    async def test_transport_failure_is_ambiguous_for_writes_and_safe_for_reads(self):
        calls = []

        def handler(request):
            calls.append(request.method)
            raise httpx.ReadTimeout("Sensitive credential and response details", request=request)

        async with ServiceNowClient(settings(), transport=httpx.MockTransport(handler)) as client:
            for operation in (lambda: client.create_incident({"correlation_id": KEY}),
                              lambda: client.update_incident(SYS_ID, {"work_notes": "message"})):
                with self.assertRaises(SnowAmbiguousWrite) as caught:
                    await operation()
                self.assertFalse(caught.exception.retryable)
                self.assertNotIn("Sensitive", str(caught.exception))
            with self.assertRaises(SnowError) as caught:
                await client.find_incident(KEY)
            self.assertTrue(caught.exception.retryable)
            self.assertNotIsInstance(caught.exception, SnowAmbiguousWrite)
        self.assertEqual(calls, ["POST", "PATCH", "GET"])

    async def test_status_errors_are_sanitized_and_never_retried_implicitly(self):
        for method, status, expected_type, retryable in (
            ("POST", 403, SnowError, False), ("PATCH", 401, SnowError, False),
            ("POST", 429, SnowError, True), ("POST", 500, SnowAmbiguousWrite, False),
            ("PATCH", 503, SnowAmbiguousWrite, False), ("GET", 503, SnowError, True),
            ("GET", 404, SnowError, False), ("POST", 302, SnowError, False),
        ):
            with self.subTest(method=method, status=status):
                calls = []

                def handler(request):
                    calls.append(request)
                    return httpx.Response(status, text="secret-response-body", headers={"Location": "https://elsewhere.test"})

                async with ServiceNowClient(settings(), transport=httpx.MockTransport(handler)) as client:
                    with self.assertRaises(expected_type) as caught:
                        if method == "POST":
                            await client.create_incident({"correlation_id": KEY})
                        elif method == "PATCH":
                            await client.update_incident(SYS_ID, {"work_notes": "message"})
                        else:
                            await client.get_incident(SYS_ID)
                self.assertEqual(len(calls), 1)
                self.assertEqual(caught.exception.status_code, status)
                self.assertEqual(caught.exception.retryable, retryable)
                self.assertNotIn("secret", str(caught.exception))
                self.assertNotIn("test-password", str(caught.exception))

    async def test_invalid_success_write_responses_are_ambiguous(self):
        responses = [httpx.Response(200, text="not-json-secret"), httpx.Response(200, json={}),
                     httpx.Response(204), httpx.Response(201, json={"result": {}}),
                     httpx.Response(201, json={"result": record(correlation_id="incorrect")}),
                     httpx.Response(201, json={"result": record(sys_id="invalid")})]
        for response in responses:
            for method in ("POST", "PATCH"):
                with self.subTest(method=method, response=response):
                    async with ServiceNowClient(settings(), transport=httpx.MockTransport(lambda request: response)) as client:
                        with self.assertRaises(SnowAmbiguousWrite) as caught:
                            if method == "POST":
                                await client.create_incident({"correlation_id": KEY})
                            else:
                                await client.update_incident(SYS_ID, {"work_notes": "message"})
                        self.assertFalse(caught.exception.retryable)
                        self.assertNotIn("not-json-secret", str(caught.exception))

    async def test_specific_incident_id_must_match_response(self):
        transport = httpx.MockTransport(lambda request: httpx.Response(200, json={
            "result": record(sys_id="f" * 32)}))
        async with ServiceNowClient(settings(), transport=transport) as client:
            with self.assertRaisesRegex(SnowError, "unexpected incident sys_id"):
                await client.get_incident(SYS_ID)
            with self.assertRaises(SnowAmbiguousWrite):
                await client.update_incident(SYS_ID, {"work_notes": "message"})


if __name__ == "__main__":
    unittest.main()
