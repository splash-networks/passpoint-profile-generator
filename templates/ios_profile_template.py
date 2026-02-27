IOS_PROFILE_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" 
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadType</key>
      <string>com.apple.wifi.managed</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
      <key>PayloadIdentifier</key>
      <string>{{ payload_identifier }}.wifi</string>
      <key>PayloadUUID</key>
      <string>{{ wifi_uuid }}</string>
      <key>PayloadDisplayName</key>
      <string>{{ profile.HomeSP.FriendlyName }} WiFi</string>

      <key>HIDDEN_NETWORK</key>
      <false/>
      <key>IsHotspot</key>
      <true/>
      <key>ServiceProviderRoamingEnabled</key>
      <true/>
      <key>DisplayedOperatorName</key>
      <string>{{ profile.HomeSP.FriendlyName }}</string>
      <key>DomainName</key>
      <string>{{ profile.HomeSP.FQDN }}</string>
      {%- if profile.HomeSP.RoamingConsortiumOI is defined %}
      <key>RoamingConsortiumOIs</key>
      <array>
        <string>{{ profile.HomeSP.RoamingConsortiumOI }}</string>
      </array>
      {%- endif %}
      <key>EAPClientConfiguration</key>
      <dict>
        {%- if profile.Credential.UsernamePassword is defined %}
        <key>AcceptEAPTypes</key>
        <array>
          <integer>{{ profile.Credential.UsernamePassword.EAPMethod.EAPType }}</integer>
        </array>
        <key>TTLSInnerAuthentication</key>
        <string>{{ profile.Credential.UsernamePassword.EAPMethod.InnerMethod }}</string>
        <key>UserName</key>
        <string>{{ profile.Credential.UsernamePassword.Username }}</string>
        <key>UserPassword</key>
        <string>{{ profile.Credential.UsernamePassword.Password }}</string>
        {%- elif profile.Credential.DigitalCertificate is defined %}
        <key>AcceptEAPTypes</key>
        <array>
          <integer>13</integer>
        </array>
        {%- elif profile.Credential.SIM is defined %}
        <key>AcceptEAPTypes</key>
        <array>
          <integer>{{ profile.Credential.SIM.EAPType }}</integer>
        </array>
        <key>OuterIdentity</key>
        <string>{{ profile.Credential.SIM.IMSI }}</string>
        {%- endif %}
        <key>TLSTrustedServerNames</key>
        <array>
          <string>{{ tls_server_name }}</string>
        </array>
        {%- if ca_cert_uuid is defined %}
        <key>PayloadCertificateAnchorUUID</key>
        <array>
          <string>{{ ca_cert_uuid }}</string>
        </array>
        {%- endif %}
      </dict>
    </dict>
    {%- if ca_cert_b64 is defined %}
    <dict>
      <key>PayloadType</key>
      <string>com.apple.security.root</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
      <key>PayloadIdentifier</key>
      <string>{{ payload_identifier }}.cert</string>
      <key>PayloadUUID</key>
      <string>{{ ca_cert_uuid }}</string>
      <key>PayloadDisplayName</key>
      <string>{{ profile.HomeSP.FQDN }} CA</string>
      <key>PayloadContent</key>
      <data>
        {{ ca_cert_b64 }}
      </data>
    </dict>
    {%- endif %}
  </array>

  <key>PayloadDisplayName</key>
  <string>{{ profile.HomeSP.FriendlyName }} Passpoint</string>
  <key>PayloadIdentifier</key>
  <string>{{ payload_identifier }}</string>
  <key>PayloadUUID</key>
  <string>{{ root_uuid }}</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
  <key>PayloadType</key>
  <string>Configuration</string>
  <key>PayloadDescription</key>
  <string>Passpoint profile for {{ profile.HomeSP.FriendlyName }}</string>
</dict>
</plist>
"""