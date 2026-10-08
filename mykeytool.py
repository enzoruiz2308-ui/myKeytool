#!/usr/bin/env python3
"""mykeytool - Simulador simplificado de Java keytool."""
import argparse
import getpass
import json
import os
import sys
from pathlib import Path
from base64 import b64encode, b64decode

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# ------------------------------------------------------------ utilidades
def ask(prompt, required=False):
    """Pide un texto por teclado. Si required=True, insiste hasta que no esté vacío."""
    while True:
        value = input(prompt).strip()
        if value or not required:
            return value
        print("  Este campo es obligatorio.")


def ask_password(prompt, min_len=6):
    """Pide una contraseña sin mostrarla y la confirma."""
    while True:
        pw = getpass.getpass(prompt)
        if len(pw) < min_len:
            print(f"  Debe tener al menos {min_len} caracteres.")
            continue
        if getpass.getpass("  Repite la contraseña: ") != pw:
            print("  Las contraseñas no coinciden.")
            continue
        return pw


def ask_dn():
    """Pide el Distinguished Name y lo devuelve como diccionario."""
    print("Datos del titular (deja vacío para omitir, salvo CN):")
    dn = {"CN": ask("  CN (nombre y apellidos): ", required=True)}
    dn["OU"] = ask("  OU (unidad organizativa): ")
    dn["O"] = ask("  O  (organización): ")
    dn["L"] = ask("  L  (localidad): ")
    dn["ST"] = ask("  ST (provincia/estado): ")
    while True:
        c = ask("  C  (país, 2 letras, ej. ES): ").upper()
        if c == "" or (len(c) == 2 and c.isalpha()):
            break
        print("  El país debe tener 2 letras.")
    dn["C"] = c
    return {k: v for k, v in dn.items() if v}  # quitamos los vacíos


def dn_to_rfc4514(dn):
    """Convierte un diccionario DN a formato RFC 4514 (CN=...,O=...)."""
    order = ["CN", "OU", "O", "L", "ST", "C"]
    parts = [f"{k}={dn[k]}" for k in order if k in dn]
    return ",".join(parts)


# ---------------------------------------------------------- Almacén cifrado
class KeyStore:
    """Almacén de claves con cifrado AES-256-GCM."""

    def __init__(self, path, master_password):
        self.path = Path(path)
        self.master_password = master_password
        self.data = {}
        if self.path.exists():
            self._load()

    def _derive_key(self, salt=None):
        """Deriva una clave de cifrado de la contraseña maestra usando PBKDF2."""
        if salt is None:
            salt = os.urandom(16)
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend(),
        )
        key = kdf.derive(self.master_password.encode())
        return key, salt

    def _load(self):
        """Carga el almacén desde disco."""
        with open(self.path, "r") as f:
            encrypted = json.load(f)
        
        salt = b64decode(encrypted["salt"])
        key, _ = self._derive_key(salt)
        
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(b64decode(encrypted["iv"]), b64decode(encrypted["tag"])),
            backend=default_backend(),
        )
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(b64decode(encrypted["data"])) + decryptor.finalize()
        self.data = json.loads(decrypted.decode())

    def _save(self):
        """Guarda el almacén cifrado en disco."""
        key, salt = self._derive_key()
        iv = os.urandom(12)
        
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
            backend=default_backend(),
        )
        encryptor = cipher.encryptor()
        data_json = json.dumps(self.data).encode()
        encrypted = encryptor.update(data_json) + encryptor.finalize()
        
        encrypted_store = {
            "salt": b64encode(salt).decode(),
            "iv": b64encode(iv).decode(),
            "tag": b64encode(encryptor.tag).decode(),
            "data": b64encode(encrypted).decode(),
        }
        
        with open(self.path, "w") as f:
            json.dump(encrypted_store, f, indent=2)

    def set_key(self, alias, private_key_pem, key_password, dn):
        """Guarda una clave privada cifrada con su contraseña."""
        self.data[alias] = {
            "private_key": private_key_pem,
            "key_password": key_password,
            "dn": dn,
        }
        self._save()

    def get_key(self, alias, key_password):
        """Recupera una clave privada del almacén."""
        if alias not in self.data:
            return None
        entry = self.data[alias]
        if entry["key_password"] != key_password:
            return None
        return entry["private_key"], entry["dn"]

    def list_aliases(self):
        """Lista todos los alias del almacén."""
        return list(self.data.keys())


# -------------------------------------------------------------- comandos
def cmd_genkeypair(args):
    store_pw = ask_password("Contraseña del almacén: ")
    alias = ask("Alias: ", required=True)
    key_pw = ask_password("Contraseña de la clave (alias): ")
    dn = ask_dn()

    print("Generando par de claves RSA de 2048 bits...")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Cifra la clave privada con la contraseña del alias
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(key_pw.encode("utf-8")),
    ).decode()

    # Guarda en el almacén
    keystore = KeyStore(args.keystore, store_pw)
    keystore.set_key(alias, private_pem, key_pw, dn)

    print(f"✓ Clave generada y almacenada")
    print(f"  Alias: {alias}")
    print(f"  DN: {dn_to_rfc4514(dn)}")


def cmd_certreq(args):
    """Genera una solicitud de firma de certificado (CSR) en formato PEM."""
    store_pw = ask_password("Contraseña del almacén: ")
    alias = ask("Alias de la clave: ", required=True)
    key_pw = ask_password("Contraseña de la clave: ")
    output_file = ask("Archivo de salida (CSR): ", required=True)

    # Carga la clave privada del almacén
    keystore = KeyStore(args.keystore, store_pw)
    result = keystore.get_key(alias, key_pw)
    
    if result is None:
        print("✗ Alias o contraseña incorrectos")
        sys.exit(1)
    
    private_pem, dn = result
    
    # Carga la clave privada desde PEM
    private_key = serialization.load_pem_private_key(
        private_pem.encode(),
        password=key_pw.encode("utf-8"),
        backend=default_backend(),
    )

    # Construye el CSR manualmente (simplificado)
    dn_rfc4514 = dn_to_rfc4514(dn)
    print(f"Generando CSR para: {dn_rfc4514}")
    
    # Para una implementación real, usaríamos cryptography.x509
    # Aquí hacemos una versión simplificada que muestra el proceso
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    
    # Construye el nombre del solicitante
    name_attrs = []
    attr_map = {
        "CN": NameOID.COMMON_NAME,
        "O": NameOID.ORGANIZATION_NAME,
        "OU": NameOID.ORGANIZATIONAL_UNIT_NAME,
        "L": NameOID.LOCALITY_NAME,
        "ST": NameOID.STATE_OR_PROVINCE_NAME,
        "C": NameOID.COUNTRY_NAME,
    }
    
    for key, oid in attr_map.items():
        if key in dn:
            name_attrs.append(x509.NameAttribute(oid, dn[key]))
    
    subject = x509.Name(name_attrs)
    
    # Genera el CSR
    csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(
        private_key, hashes.SHA256(), backend=default_backend()
    )
    
    # Guarda el CSR en PEM
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()
    
    with open(output_file, "w") as f:
        f.write(csr_pem)
    
    print(f"✓ CSR generado y guardado en: {output_file}")


def cmd_list(args):
    """Lista todos los alias del almacén."""
    store_pw = ask_password("Contraseña del almacén: ")
    keystore = KeyStore(args.keystore, store_pw)
    aliases = keystore.list_aliases()
    
    if not aliases:
        print("El almacén está vacío")
    else:
        print("Alias en el almacén:")
        for alias in aliases:
            entry = keystore.data[alias]
            dn_str = dn_to_rfc4514(entry["dn"])
            print(f"  • {alias}: {dn_str}")


# ------------------------------------------------------------------- CLI
def build_parser():
    parser = argparse.ArgumentParser(
        prog="mykeytool.py",
        description="Simulador simplificado de Java keytool.",
    )

    # Solo se puede elegir un comando a la vez
    comandos = parser.add_mutually_exclusive_group(required=True)
    comandos.add_argument(
        "--genkeypair", action="store_true",
        help="genera un par de claves RSA 2048 y lo guarda en el almacén",
    )
    comandos.add_argument(
        "--certreq", action="store_true",
        help="genera una solicitud de firma de certificado (CSR) en PEM",
    )
    comandos.add_argument(
        "--list", action="store_true",
        help="lista todos los alias del almacén",
    )

    parser.add_argument(
        "--keystore", default="keystore.pks", metavar="ARCHIVO",
        help="archivo del almacén (por defecto: keystore.pks)",
    )
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    
    try:
        if args.genkeypair:
            cmd_genkeypair(args)
        elif args.certreq:
            cmd_certreq(args)
        elif args.list:
            cmd_list(args)
    except KeyboardInterrupt:
        print("\n✗ Operación cancelada")
        sys.exit(1)
    except Exception as e:
        print(f"✗ Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.genkeypair:
        cmd_genkeypair(args)
    elif args.certreq:
        cmd_certreq(args)
    else:
        parser.print_help()  # sin argumentos: mostrar la ayuda
    return 0


if __name__ == "__main__":
    sys.exit(main())