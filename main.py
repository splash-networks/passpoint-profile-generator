import os
import base64
import uuid
import jinja2
import uvicorn
import xml.etree.ElementTree as ET

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

import templates.profile_template
import templates.ios_profile_template
import restapi


def create_profile(file_name: str, profile_data: dict):
    """
    Used to create a xml passpoint file

    :param file_name: Name of the file with .xml at the end
    :param profile_data: Profile data following schema profile
    :return: None
    """
    if file_name[-4:] != '.xml':
        file_name = file_name + '.xml'

    env = jinja2.Environment()
    env.filters['b64encode'] = lambda s: base64.b64encode(s.encode('utf-8')).decode('utf-8')

    jinja_template = env.from_string(templates.profile_template.PROFILE_TEMPLATE)
    profile_xml = jinja_template.render(profile=profile_data)

    with open('profiles/' + file_name, 'w') as xml_file:
        xml_file.write(profile_xml)

    return None


def _cert_to_b64_der(cert_data: bytes) -> str:
    """Convert PEM or DER certificate bytes to base64-encoded DER string."""
    if b'-----BEGIN' in cert_data:
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())
        cert_data = cert.public_bytes(serialization.Encoding.DER)
    return base64.b64encode(cert_data).decode('utf-8')


def _render_ios_template(profile_data: dict, cert_data: bytes = None,
                         tls_server_name: str = None, payload_identifier: str = None) -> str:
    """
    Core rendering logic shared between create_ios_profile and build_ios_mobileconfig.
    """
    fqdn = profile_data['HomeSP']['FQDN']

    if payload_identifier is None:
        fqdn_parts = fqdn.split('.')
        reversed_fqdn = '.'.join(reversed(fqdn_parts))
        payload_identifier = f"{reversed_fqdn}.passpoint"
    if tls_server_name is None:
        tls_server_name = fqdn

    root_uuid = str(uuid.uuid4()).upper()
    wifi_uuid = str(uuid.uuid4()).upper()
    ca_cert_uuid = str(uuid.uuid4()).upper() if cert_data else None
    ca_cert_b64 = _cert_to_b64_der(cert_data) if cert_data else None

    jinja_template = jinja2.Template(templates.ios_profile_template.IOS_PROFILE_TEMPLATE)
    return jinja_template.render(
        profile=profile_data,
        payload_identifier=payload_identifier,
        tls_server_name=tls_server_name,
        root_uuid=root_uuid,
        wifi_uuid=wifi_uuid,
        ca_cert_uuid=ca_cert_uuid,
        ca_cert_b64=ca_cert_b64,
    )


def create_ios_profile(file_name: str, profile_data: dict,
                       ca_cert_path: str = None, tls_server_name: str = None,
                       payload_identifier: str = None):
    """
    Create an Apple .mobileconfig Passpoint profile saved to disk.
    """
    if not file_name.endswith('.mobileconfig'):
        file_name = file_name + '.mobileconfig'

    cert_data = None
    if ca_cert_path:
        with open('certificates/' + ca_cert_path, 'rb') as f:
            cert_data = f.read()

    mobileconfig = _render_ios_template(profile_data, cert_data, tls_server_name, payload_identifier)

    with open('profiles/' + file_name, 'w') as f:
        f.write(mobileconfig)


def build_ios_mobileconfig(profile_xml: str, cert_data: bytes,
                           tls_server_name: str = None) -> str:
    """
    Build an iOS mobileconfig string directly from a pre-existing Android XML profile
    and raw certificate bytes. Used by the /passpoint.mobileconfig endpoint so you
    can reuse the same XML profile for both platforms.
    """
    root = ET.fromstring(profile_xml)

    def get_value(parent, node_name):
        for node in parent.iter('Node'):
            name_el = node.find('NodeName')
            if name_el is not None and name_el.text == node_name:
                value_el = node.find('Value')
                if value_el is not None:
                    return value_el.text
        return None

    profile_data = {
        'HomeSP': {
            'FriendlyName': get_value(root, 'FriendlyName'),
            'FQDN': get_value(root, 'FQDN'),
        },
        'Credential': {
            'Realm': get_value(root, 'Realm'),
            'UsernamePassword': {
                'Username': get_value(root, 'Username'),
                # Android stores password base64-encoded, decode it back for iOS
                'Password': base64.b64decode(get_value(root, 'Password')).decode('utf-8'),
                'EAPMethod': {
                    'EAPType': int(get_value(root, 'EAPType')),
                    'InnerMethod': get_value(root, 'InnerMethod'),
                }
            }
        }
    }

    return _render_ios_template(profile_data, cert_data, tls_server_name)


def start_uvicorn():
    """ Starts up uvicorn with the FastAPI file listening on all interfaces over port 80 """
    profiles_folder = os.listdir('profiles')
    certificates_folder = os.listdir('certificates')
    for index, file in enumerate(profiles_folder):
        if file[-4:] == '.xml':
            break
        if index + 1 == len(profiles_folder):
            print('Missing profile files in folder profile.\n'
                  'Please upload a .xml profile into that folder or "Generate profile a file"')
            return None
    for index, file in enumerate(certificates_folder):
        if file[-4:] == '.cer':
            break
        if index + 1 == len(certificates_folder):
            print('Could not find a .cer file in the certificates folder.\n'
                  'Please upload a .cer file into that folder"')
            return None
    print('Starting up web server on port 8000.\n'
          'Please be aware that it is unsafe to send files over the internet as they are unencrypted\n'
          'Using web browser navigate to http://hostip:8000/passpoint.config\n'
          'For iOS devices open Safari and navigate to http://hostip:8000/passpoint.mobileconfig')
    uvicorn.run(restapi.app, host='0.0.0.0')


def profile_generator():
    """
    Walks user through creating a passpoint profile for Android and iOS

    :return:
    """
    profile_data = {'HomeSP': {}, 'Credential': {}}
    profile_data['HomeSP'].update(
        {'FriendlyName': input('What is the friendly name of the network? ')})
    profile_data['HomeSP'].update(
        {'FQDN': input('What is the domain for the network? ')})
    choice = input('Does the network have a roaming consortium ID? (y/n) ')
    while choice not in ['y', 'n', 'yes', 'no', 'Yes', 'No', 'true', 'false', 'True', 'False']:
        choice = input('Response: {choice} was not valid input.\n'
                       'Does the network have a roaming consortium ID? (y/n) '.format(choice=choice))
    if choice in ['y', 'yes', 'Yes', 'true', 'True']:
        choice = True
    else:
        choice = False
    if choice:
        profile_data['HomeSP'].update(
            {'RoamingConsortiumOI': input('What is the roaming consortium ID the network? ')})
    profile_data['Credential'].update(
        {'Realm': input('What is the domain that the credential belongs to? ')})

    eap_types = 'EAP-TTLS (21), EAP-TLS (13), EAP-SIM (18), EAP-AKA (23), EAP-AKA (50)'

    choice = input('What type of credentials does this network use? (Username/Password, EAP-TLS, SIM) ')
    while choice not in ['Username/Password', 'username/password', 'user/pass', 'username', 'user', 'u',
                         'EAP-TLS', 'eap-tls', 'e', 'SIM', 'sim', 's']:
        choice = input('Response: {choice} was not valid input.\n'
                       'What type of credentials does this network use?'
                       '(Username/Password, EAP-TLS, SIM) '.format(choice=choice))
    if choice in ['Username/Password', 'username/password', 'user/pass', 'username', 'user', 'u']:
        profile_data['Credential'].update({'UsernamePassword': {}})
        profile_data['Credential']['UsernamePassword'].update(
            {'Username': input('What is the username? ')})
        profile_data['Credential']['UsernamePassword'].update(
            {'Password': input('What is the password? ')})
        profile_data['Credential']['UsernamePassword'].update({'EAPMethod': {}})
        profile_data['Credential']['UsernamePassword']['EAPMethod'].update(
            {'EAPType': str(input('What is the EAP type for the credential?\n' + eap_types + '\n'))})
        profile_data['Credential']['UsernamePassword']['EAPMethod'].update(
            {'InnerMethod': input('What is the inner method for the credential? '
                                  '(PAP, CHAP, MS-CHAP, or MS-CHAP-V2) ')})
    elif choice in ['EAP-TLS', 'eap-tls', 'e']:
        profile_data['Credential'].update({'DigitalCertificate': {}})
        profile_data['Credential']['DigitalCertificate'].update(
            {'CertificateType': input('Certificate type (x509v3) ') or 'x509v3'})
        profile_data['Credential']['DigitalCertificate'].update(
            {'CertSHA256Fingerprint': input('What is the fingerprint of the certificate? ')})
    elif choice in ['SIM', 'sim', 's']:
        profile_data['Credential'].update({'SIM': {}})
        profile_data['Credential']['SIM'].update(
            {'IMSI': input('What is the international mobile subscriber identity? ')})
        profile_data['Credential']['SIM'].update(
            {'Username': str(input('What is the EAP type for the credential?\n' + eap_types + '\n'))})

    file_name = input('Save the profile as? ')

    # Generate Android profile
    create_profile(file_name, profile_data)
    print(f'Android profile saved as profiles/{file_name}.xml')

    # Optionally generate iOS profile too
    choice = input('Also generate an iOS .mobileconfig profile? (y/n) ')
    if choice in ['y', 'yes', 'Yes']:
        cert_files = [f for f in os.listdir('certificates') if f.endswith('.cer')]
        if not cert_files:
            print('No .cer files found in certificates/ folder, skipping iOS profile.')
        else:
            if len(cert_files) == 1:
                ca_cert = cert_files[0]
            else:
                print('Available certificates: ' + ', '.join(cert_files))
                ca_cert = input('Which certificate to use? ')
            tls_server_name = input('TLS server name (CN of RADIUS cert, leave blank to use FQDN)? ').strip() or None
            create_ios_profile(file_name, profile_data,
                               ca_cert_path=ca_cert,
                               tls_server_name=tls_server_name)
            print(f'iOS profile saved as profiles/{file_name}.mobileconfig')

    return None


def main():
    choice = None
    print('Welcome to the Android Passpoint profile generator.\n'
          'Please enter the number before the option to continue with that option\n')
    while choice not in [4, '4', 'exit', 'quit', 'close', 'q']:
        choice = input('1. Instructions\n'
                       '2. Generate profile a file\n'
                       '3. Start web server\n'
                       '4. Exit\n')
        if choice in [1, "1", "Instructions", "instructions", "help", "Help"]:
            print('This is to walk through creating Passpoint profile for Android and iOS devices.\n'
                  'The first part will ask some questions to help generate a profile for the device.\n'
                  'Next section will start a webserver so the device can download the profile.\n'
                  'On Android navigate to: '
                  'http://{ip_address}:8000/passpoint.config?profile={profile}&certificate={certificate}\n'
                  'On iOS open Safari and navigate to: '
                  'http://{ip_address}:8000/passpoint.mobileconfig?profile={profile}&certificate={certificate}\n')
        elif choice in [2, "2"]:
            profile_generator()
        elif choice in [3, "3"]:
            start_uvicorn()
        elif choice in [4, '4', 'exit', 'quit', 'close', 'q']:
            print('Quiting...')
            break
        else:
            print('Invalid Option: {} Please choose an option below...'.format(choice))


if __name__ == '__main__':
    main()