from app.scrubber import MASK, scrub

APPSETTINGS = """{
  "$schema": "https://json.schemastore.org/appsettings.json",
  "Logging": { "LogLevel": { "Default": "Information", "Microsoft.AspNetCore": "Warning" } },
  "AllowedHosts": "*",
  "ConnectionStrings": {
    "Default": "Server=tcp:sql-prod01.sokigo.internal,1433;Initial Catalog=FbProd;User ID=app_user;Password=S3cr3t!pw;Encrypt=True"
  },
  "AzureAd": {
    "Instance": "https://login.microsoftonline.com/",
    "Domain": "contoso.onmicrosoft.com",
    "TenantId": "6f1c2a4e-9b7d-4c1e-8a3f-2d5b7e9c1a0b",
    "ClientId": "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d",
    "ClientSecret": "abc8Q~Zx9yW7vU5tS3rQ1pO-nM_lK.jIhGfEdCbA"
  },
  "Api": { "BaseUrl": "https://api.kund.se/v2/", "ApiKey": "k3y-9f8e7d6c5b4a" },
  "Kestrel": { "Endpoints": { "Http": { "Url": "http://0.0.0.0:5000" } } },
  "Smtp": { "Host": "10.20.30.40", "Port": 25 }
}"""

WEB_CONFIG = """<?xml version="1.0" encoding="utf-8"?>
<configuration xmlns="http://schemas.microsoft.com/.NetConfiguration/v2.0">
  <connectionStrings>
    <add name="Main" connectionString="Data Source=SQLPROD01\\INST;Initial Catalog=Ecos;User Id=sa;Password=hunter2;" providerName="System.Data.SqlClient" />
  </connectionStrings>
  <appSettings>
    <add key="ida:Tenant" value="kommun.onmicrosoft.com" />
    <add key="ida:ClientId" value="11111111-2222-4333-8444-555555555555" />
    <add key="ReportServer" value="RPT01" />
  </appSettings>
  <assemblies>
    <add assembly="System.Web.Mvc, Version=5.2.7.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" />
  </assemblies>
  <Password>topsecret</Password>
</configuration>"""

ENV = """DB_HOST=db01.corp.local
DB_NAME=geodata
DB_PASSWORD=p#ss w0rd
API_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789
STORAGE=DefaultEndpointsProtocol=https;AccountName=stgprod;AccountKey=Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZg==;EndpointSuffix=core.windows.net
LOG_LEVEL=debug
"""


def test_appsettings():
    r = scrub(APPSETTINGS)
    out = r.text
    for secret in ["sql-prod01.sokigo.internal", "FbProd", "app_user", "S3cr3t!pw",
                   "contoso.onmicrosoft.com", "6f1c2a4e", "0a1b2c3d", "abc8Q~", "api.kund.se",
                   "k3y-9f8e7d6c5b4a", "10.20.30.40"]:
        assert secret not in out, secret
    for keep in ["https://json.schemastore.org/appsettings.json", "Microsoft.AspNetCore",
                 "https://login.microsoftonline.com/", "http://0.0.0.0:5000", '"AllowedHosts": "*"',
                 "Encrypt=True", '"Port": 25', "Information"]:
        assert keep in out, keep
    assert r.counts["tenant_id"] == 1 and r.counts["client_id"] == 1 and r.counts["client_secret"] == 1


def test_web_config():
    out = scrub(WEB_CONFIG).text
    for secret in ["SQLPROD01", "Ecos", "sa;", "hunter2", "kommun.onmicrosoft.com",
                   "11111111-2222", "RPT01", "topsecret"]:
        assert secret not in out, secret
    for keep in ["Version=5.2.7.0", "PublicKeyToken=31bf3856ad364e35", "System.Data.SqlClient",
                 "schemas.microsoft.com", 'version="1.0"']:
        assert keep in out, keep


def test_env():
    out = scrub(ENV).text
    for secret in ["db01.corp.local", "geodata", "p#ss w0rd", "ghp_", "stgprod", "Zm9vYmFy"]:
        assert secret not in out, secret
    assert "EndpointSuffix=core.windows.net" in out
    assert "LOG_LEVEL=debug" in out


def test_urls_ipv6_custom_and_toggles():
    text = "see https://intranet.kund.local/app and fe80::1ff:fe23:4567:890a, customer Kommunen AB"
    r = scrub(text, custom_terms=["Kommunen AB"])
    assert r.text == f"see {MASK} and {MASK}, customer {MASK}"
    r = scrub(text, categories=["ip"])
    assert "intranet.kund.local" in r.text and "fe80" not in r.text


def test_idempotent_and_noise():
    once = scrub(APPSETTINGS).text
    assert scrub(once).text == once
    noise = "Using System.IO and Newtonsoft.Json in appsettings.Development.json, see ASP.NET docs."
    assert scrub(noise).text == noise


def test_custom_keys():
    text = ('{"NoReplyEmailAddress":"THIS PART TO BE REDACTED", "Shell": {"ShellTitle": "Kund Portal"}}\n'
            '<add key="App:ShellTitle" value="Kund" />\n'
            'shell_title: Kund Portal\n'
            'Server=x.y.local;NoReplyEmailAddress=a@b.se;Encrypt=True\n')
    r = scrub(text, custom_keys=["NoReplyEmailAddress", "ShellTitle"])
    assert r.text == (f'{{"NoReplyEmailAddress":"{MASK}", "Shell": {{"ShellTitle": "{MASK}"}}}}\n'
                      f'<add key="App:ShellTitle" value="{MASK}" />\n'
                      f'shell_title: {MASK}\n'
                      f'Server={MASK};NoReplyEmailAddress={MASK};Encrypt=True\n')


def test_xml_element_value_attribute():
    text = """<endpoint address="net.tcp://APPSRV01:808/Service.svc" binding="netTcpBinding">
       <identity>
          <userPrincipalName
            value="svc_ecos@kommun.se" />
          <dns value="APPSRV01" />
       </identity>
    </endpoint>
    <applicationSettings>
      <setting name="ShellTitle" serializeAs="String">
        <value>Kommunen Bygglov</value>
      </setting>
      <setting name="PageSize" serializeAs="String"><value>50</value></setting>
    </applicationSettings>
    <userPrincipalName value="" />"""
    r = scrub(text, custom_keys=["ShellTitle"])
    for secret in ["svc_ecos", "kommun.se", "APPSRV01", "Kommunen Bygglov"]:
        assert secret not in r.text, secret
    assert "<value>50</value>" in r.text
    assert '<userPrincipalName value="" />' in r.text
    assert "<userPrincipalName\n            value=\"*REDACTED*\" />" in r.text


def test_allowlist():
    r = scrub("call https://api.kund.se/x", allowlist=["*.kund.se"])
    assert "api.kund.se" in r.text
