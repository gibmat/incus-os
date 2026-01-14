#!/bin/sh

# This is a TEST script to generate TEST secure boot PK/KEK/db variable updates.
# DON'T let these variables anywhere near a production environment -- we don't want our own PKfail. :)

# Note: There are at least two different tools available in Debian to create and sign the EFI lists,
# efitools and sbsigntool. At the moment, sbsigntool is broken (https://github.com/systemd/systemd/issues/34316#issuecomment-2337311589)
# so we use the commands from efitools.

set -e

OS_NAME="TestOS"
UUID="433f8160-9ab6-4407-8e38-12d70e1d54e5"

if [ -d certs/efi/ ]; then
    echo "Test secure boot signed keys already appear to have been generated, exiting."
    exit 0
fi

mkdir -p certs/efi/

# PK
openssl x509 -in "certs/${OS_NAME}-secureboot-PK-R1.crt" -out certs/efi/secureboot-PK-R1.der -outform DER
cert-to-efi-sig-list -g "${UUID}" "certs/${OS_NAME}-secureboot-PK-R1.crt" certs/efi/PK.esl
sign-efi-sig-list -g "${UUID}" -c "certs/${OS_NAME}-secureboot-PK-R1.crt" -k "certs/${OS_NAME}-secureboot-PK-R1.key" PK certs/efi/PK.esl certs/efi/PK.auth

# KEKs
openssl x509 -in "certs/${OS_NAME}-secureboot-KEK-R1.crt" -out certs/efi/secureboot-KEK-R1.der -outform DER
openssl x509 -in "certs/${OS_NAME}-secureboot-KEK-R2.crt" -out certs/efi/secureboot-KEK-R2.der -outform DER
cert-to-efi-sig-list -g "${UUID}" "certs/${OS_NAME}-secureboot-KEK-R1.crt" "certs/efi/${OS_NAME}-kek-1.esl"
sign-efi-sig-list -g "${UUID}" -c "certs/${OS_NAME}-secureboot-PK-R1.crt" -k "certs/${OS_NAME}-secureboot-PK-R1.key" KEK "certs/efi/${OS_NAME}-kek-1.esl" certs/efi/KEK.auth

# First two trusted secure boot keys
openssl x509 -in "certs/${OS_NAME}-secureboot-1-R1.crt" -out certs/efi/secureboot-DB-1.der -outform DER
openssl x509 -in "certs/${OS_NAME}-secureboot-2-R1.crt" -out certs/efi/secureboot-DB-2.der -outform DER
cert-to-efi-sig-list -g "${UUID}" "certs/${OS_NAME}-secureboot-1-R1.crt" "certs/efi/${OS_NAME}-secureboot-1.esl"
cert-to-efi-sig-list -g "${UUID}" "certs/${OS_NAME}-secureboot-2-R1.crt" "certs/efi/${OS_NAME}-secureboot-2.esl"

cp scripts/test/microsoft-certs/db/MicCorUEFCA2011_2011-06-27.der certs/efi/
cp scripts/test/microsoft-certs/db/MicWinProPCA2011_2011-10-19.der certs/efi/
cert-to-efi-sig-list -g "${UUID}" scripts/test/microsoft-certs/db/MicCorUEFCA2011_2011-06-27.crt certs/efi/MicCorUEFCA2011_2011-06-27.esl
cert-to-efi-sig-list -g "${UUID}" scripts/test/microsoft-certs/db/MicWinProPCA2011_2011-10-19.crt certs/efi/MicWinProPCA2011_2011-10-19.esl

cat certs/efi/MicCorUEFCA2011_2011-06-27.esl certs/efi/MicWinProPCA2011_2011-10-19.esl "certs/efi/${OS_NAME}-secureboot-1.esl" "certs/efi/${OS_NAME}-secureboot-2.esl" > certs/efi/DB.esl
sign-efi-sig-list -g "${UUID}" -c "certs/${OS_NAME}-secureboot-KEK-R1.crt" -k "certs/${OS_NAME}-secureboot-KEK-R1.key" db certs/efi/DB.esl certs/efi/DB.auth

mkdir -p certs/efi/updates/

# Prepare a db update
FINGERPRINT=$(openssl x509 -in "certs/${OS_NAME}-secureboot-3-R1.crt" -noout -fingerprint -sha256 | cut -d '=' -f2 | tr -d ':')
cert-to-efi-sig-list -g "${UUID}" "certs/${OS_NAME}-secureboot-3-R1.crt" "certs/efi/updates/db_${FINGERPRINT}.esl"
sign-efi-sig-list -g "${UUID}" -a -c "certs/${OS_NAME}-secureboot-KEK-R1.crt" -k "certs/${OS_NAME}-secureboot-KEK-R1.key" db "certs/efi/updates/db_${FINGERPRINT}.esl" "certs/efi/updates/db_${FINGERPRINT}.auth"

# Prepare a dbx update
FINGERPRINT=$(openssl x509 -in "certs/${OS_NAME}-secureboot-4-R1.crt" -noout -fingerprint -sha256 | cut -d '=' -f2 | tr -d ':')
cert-to-efi-sig-list -g "${UUID}" "certs/${OS_NAME}-secureboot-4-R1.crt" "certs/efi/updates/dbx_${FINGERPRINT}.esl"
sign-efi-sig-list -g "${UUID}" -a -c "certs/${OS_NAME}-secureboot-KEK-R1.crt" -k "certs/${OS_NAME}-secureboot-KEK-R1.key" dbx "certs/efi/updates/dbx_${FINGERPRINT}.esl" "certs/efi/updates/dbx_${FINGERPRINT}.auth"
