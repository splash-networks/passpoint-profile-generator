# Passpoint 802.11u Profile Generator

Forked from [here](https://github.com/omenoen/android_passpoint).

This tool can be used to build Passpoint profiles for Android and iOS.

## Usage

### CLI Tool

CLI based tool to walk a user through generating and starting up a web server. RADIUS ca.cer file will need to be put into the certificate folder.

``` python main.py```

### Just Web Server

For Android: Both the profile xml file and the RADIUS server ca.cer file will need to be supplied.
For iOS: Only the profile mobileconfig file needs to be referenced. The RADIUS CA certificate was already included in the `main.py` wizard.

Profiles

```/profiles/<profile>.xml```
```/profiles/<profile>.mobileconfig```

Certificates

```/certificates/<certificate>.cer```

Start web server

``` python -m uvicorn --host 0.0.0.0 restapi:app```

## Uploading to Android

Using chrome navigate to:

```
http://{serverIP}:8000/passpoint.config?profile={profile.xml}&certificate={certificate}
```

This should prompt you to install the profile. If there was any error the Android device will return a generic error.

## Uploading to iOS

Using Safari navigate to:

```
http://{serverIP}:8000/passpoint.mobileconfig?profile={profile.mobileconfig}
```

There will be an option to install the profile.

## Additional tool

For examples on using the API navigate to `http://{serverIP}:8000/docs`