# Mobile App (Flutter — Android & iOS)

Cross-platform Flutter client for the Self-Healing SOC backend.

## Features
- JWT login with role support (admin / analyst / viewer)
- Overview dashboard with stat cards
- Security events list with one-tap **Analyze** (ML + MITRE mapping)
- Incident list with simulated response / healing action
- Dark SOC theme

## Setup

```bash
cd mobile_app
flutter create .        # generates android/ and ios/ folders (first time only)
flutter pub get
flutter run
```

Point the API URL at your backend:

| Target | URL to use |
|---|---|
| Android emulator | `http://10.0.2.2:8000` |
| iOS simulator | `http://127.0.0.1:8000` |
| Physical device | `http://<your-laptop-LAN-IP>:8000` |

## Builds

```bash
# Android APK
flutter build apk --release
# -> build/app/outputs/flutter-apk/app-release.apk

# iOS (requires macOS + Xcode + Apple Developer signing)
flutter build ios --release
```
