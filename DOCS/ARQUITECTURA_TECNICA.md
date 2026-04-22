# Arquitectura y Especificaciones Técnicas

## 📐 Diagrama de Flujo - EXPORT-PEK

```
┌─────────────────────────────────────────────────────────────┐
│ CLI: export-pek                                             │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│ _load_input(component_1) | _load_input(component_2)         │
│ (Archivo O String Hex)                                      │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│ recombine_kek()                                             │
│ ├─ Convierte a bytes: bytes.fromhex()                       │
│ ├─ XOR binario: bytes(b1 ^ b2 for b1, b2 in zip())         │
│ └─ Valida: debe ser 32 bytes (AES-256)                      │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│ validate_kck_kcv(kek, expected_kcv)                         │
│ ├─ Genera zero_block (16 bytes)                             │
│ ├─ Computa CMAC: cmac.CMAC(AES(kek))                        │
│ ├─ Extrae KCV: cmac_result[:3]                              │
│ └─ Compara: computed_kcv == expected_kcv                    │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│ generate_and_export_pek(kek)                                │
│ ├─ Genera PEK: os.urandom(16)                               │
│ ├─ Computa PEK KCV: compute_kcv(pek) → AES-CMAC            │
│ ├─ Crea Header TR-31:                                       │
│ │  ├─ version_id="D" (TDES Double)                          │
│ │  ├─ key_usage="PE" (PIN Encryption)                      │
│ │  ├─ algorithm="T" (TDES)                                  │
│ │  ├─ mode_of_use="E" (Encrypt/Decrypt)                    │
│ │  └─ exportability="N" (Non-exportable)                    │
│ ├─ Envuelve: tr31_module.wrap(kek, header, pek)            │
│ └─ Retorna: (tr31_hex_string, pek_kcv_hex)                 │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│ Guardar a archivo                                           │
│ └─ write(out, tr31_hex_string)                              │
└─────────────────────────────────────────────────────────────┘
```

## 📐 Diagrama de Flujo - IMPORT-BDK

```
┌─────────────────────────────────────────────────────────────┐
│ CLI: import-bdk                                             │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│ _load_input(component_1, component_2, bdk_keyblock)         │
│ (Archivo O String Hex)                                      │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│ recombine_kek() → validate_kck_kcv()                        │
│ (igual a EXPORT-PEK)                                        │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│ unwrap_bdk(tr31_block_hex, kek)                             │
│ ├─ Desenvuelve: tr31_module.unwrap(kek, tr31_block)        │
│ ├─ Extrae header y bdk_bytes                                │
│ └─ Retorna: bdk_bytes (usualmente 16 o 32 bytes)           │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│ Validación Inteligente de BDK KCV                           │
│ ├─ SI len(bdk) == 16 (TDES):                                │
│ │  ├─ compute_kcv_tdes(bdk)                                 │
│ │  ├─ Cifra: Cipher(TripleDES(bdk), ECB())                 │
│ │  ├─ Entrada: 8 bytes de ceros                             │
│ │  └─ KCV: encrypted[:3].hex()                              │
│ ├─ SI len(bdk) == 32 (AES-256):                             │
│ │  ├─ compute_kcv(bdk)                                      │
│ │  ├─ CMAC: cmac.CMAC(AES(bdk))                             │
│ │  ├─ Entrada: 16 bytes de ceros                            │
│ │  └─ KCV: cmac[:3].hex()                                   │
│ └─ Compara: computed_bdk_kcv == expected_bdk_kcv            │
└─────────────────────────────────────────────────────────────┘
```

## 🔐 Especificación de Seguridad

### Algoritmos Criptográficos

| Operación | Algoritmo | Modo | Tamaño | Estándar |
|-----------|-----------|------|--------|----------|
| KEK Recombinación | XOR Binario | - | 32 bytes | ANSI X9.143 |
| KEK KCV | AES-256 | CMAC | 6 chars hex | NIST |
| PEK | Random/TDES | - | 16 bytes | TR-31 |
| PEK KCV | AES-256 | CMAC | 6 chars hex | NIST |
| BDK (TDES) | TripleDES | ECB | 16 bytes | TDES |
| BDK KCV (TDES) | TripleDES | ECB | 6 chars hex | NIST |
| BDK (AES) | AES-256 | CMAC | 32 bytes | AES |
| BDK KCV (AES) | AES-256 | CMAC | 6 chars hex | NIST |
| TR-31 Wrap | TDES | ECB | Variable | TR-31 |

### Longitudes de Clave

| Tipo | Longitud | Formato | Uso |
|------|----------|---------|-----|
| KEK Componente | 32 bytes | 64 hex chars | Recombinación XOR |
| KEK Combinada | 32 bytes | 64 hex chars | Encriptación/Desencriptación |
| PEK | 16 bytes | 32 hex chars | Encriptación de PIN |
| BDK (TDES) | 16 bytes | 32 hex chars | Derivación DUKPT |
| BDK (AES) | 32 bytes | 64 hex chars | Derivación alternativa |
| KSN | 10 bytes | 20 hex chars | Derivación DUKPT |
| KCV | 3 bytes | 6 hex chars | Verificación de integridad |

### Validaciones de Entrada

```
recombine_kek():
  ├─ component_1: archivo existente O 64 hex chars
  ├─ component_2: archivo existente O 64 hex chars
  ├─ XOR result: debe ser 32 bytes
  └─ Si no: ValidationError

validate_kck_kcv():
  ├─ kek: exactamente 32 bytes
  ├─ expected_kcv: 6 hex chars
  ├─ Calcula: AES-CMAC(kek, zero_block[:3])
  └─ Si no coincide: SecurityError

generate_and_export_pek():
  ├─ kek: exactamente 32 bytes
  ├─ Genera PEK: 16 bytes random
  ├─ TR-31 wrap: psec.tr31.wrap(kek, header, pek)
  └─ Si falla: SecurityError

unwrap_bdk():
  ├─ tr31_block: archivo existente O hex string
  ├─ kek: exactamente 32 bytes
  ├─ Desenvuelve: tr31_module.unwrap(kek, tr31_block)
  └─ Si falla: IntegrityError o ValidationError

BDK KCV Validation:
  ├─ SI len(bdk) == 16:
  │  ├─ TripleDES ECB encrypt(zero_block[8])[:3]
  │  └─ Si no coincide: IntegrityError
  ├─ SI len(bdk) == 32:
  │  ├─ AES-CMAC(bdk, zero_block[16])[:3]
  │  └─ Si no coincide: IntegrityError
  └─ SI otro tamaño: ValidationError
```

## 🛡️ Manejo de Excepciones

```
Exception Hierarchy:
KeyExchangeException (base)
├─ SecurityError
│  ├─ KEK KCV validation failed
│  ├─ TR-31 unwrap failed (no auth/mac/integrity)
│  ├─ Library not available (psec/dukpt)
│  └─ Unexpected crypto errors
├─ ValidationError
│  ├─ Invalid hex format
│  ├─ Wrong key size
│  ├─ File read errors
│  ├─ Empty strings
│  └─ Invalid component length
└─ IntegrityError
   ├─ TR-31 integrity check failed
   ├─ BDK KCV mismatch
   └─ Authentication failures
```

## 📁 Entrada Flexible (Cero Hardcoding)

### Lógica de _load_input()

```python
def _load_input(value: str) -> str:
    file_path = Path(value).expanduser()
    
    # Paso 1: ¿Es una ruta existente?
    if file_path.exists() and file_path.is_file():
        try:
            return f.read().strip()  # Leer contenido
        except IOError as e:
            raise ValidationError(f"Cannot read file: {e}")
    
    # Paso 2: Tratar como string hex
    return value
```

### Ejemplos de Uso

| Input | Tipo | Resultado |
|-------|------|-----------|
| `"/tmp/kek.hex"` | Archivo | Lee contenido del archivo |
| `"./components/comp1.txt"` | Archivo | Lee contenido del archivo |
| `"0123abcd..."` | Hex | Devuelve el mismo string |
| `"/no/existe"` | Hex | Devuelve string como-es (fallará después en validación) |
| `""` | Vacío | Lanza ValidationError |

## 🔄 Integración con Sistemas Externos

### Interfaz psec (TR-31)

```python
# Wrap
header = tr31_module.Header(
    version_id="D",           # Obligatorio: versión del formato
    key_usage="PE",           # Obligatorio: PE = PIN Encryption
    algorithm="T",            # Obligatorio: T = TDES
    mode_of_use="E",          # Obligatorio: E = Encrypt/Decrypt
    exportability="N",        # Obligatorio: N = Non-exportable
)
tr31_hex = tr31_module.wrap(kek, header, pek)

# Unwrap
header, bdk_bytes = tr31_module.unwrap(kek, tr31_hex)
```

### Interfaz dukpt

```python
# Derivación
working_key = dukpt_lib.derive(bdk, ksn_bytes)

# Desencriptación
decryptor = Cipher(
    algorithms.TripleDES(working_key),
    modes.ECB(),
    backend=default_backend()
).decryptor()
plaintext = decryptor.update(ciphertext) + decryptor.finalize()
```

## 📊 Matriz de Salidas

### Export-PEK Output

```
stdout:
SUCCESS: PEK generated and exported
PEK_KCV=ABCDEF

stderr:
✓ KEK components loaded
✓ KEK validation passed
✓ PEK generated and wrapped in TR-31
✓ TR-31 keyblock saved to: /path/to/output.tr31

Exit Code: 0 (success) | 1 (failure)
```

### Import-BDK Output (TDES)

```
stdout:
SUCCESS: BDK import and validation passed
BDK_KCV=FEDCBA
BDK_SIZE=16

stderr:
✓ KEK components loaded
✓ KEK validation passed
✓ BDK unwrapped successfully (16 bytes)
✓ Using TDES ECB mode for BDK KCV computation
✓ BDK KCV validation passed

Exit Code: 0 (success) | 1 (failure)
```

### Import-BDK Output (AES)

```
stdout:
SUCCESS: BDK import and validation passed
BDK_KCV=FEDCBA
BDK_SIZE=32

stderr:
✓ KEK components loaded
✓ KEK validation passed
✓ BDK unwrapped successfully (32 bytes)
✓ Using AES-CMAC mode for BDK KCV computation
✓ BDK KCV validation passed

Exit Code: 0 (success) | 1 (failure)
```

## 🚀 Requisitos de Producción

- Python 3.8+
- psec >= 0.9.0 (TR-31 support)
- dukpt >= 2.0.0 (DUKPT derivation)
- cryptography >= 3.4.8
- HSM para almacenamiento seguro de KEK en producción
- Auditoría y logging de todas las operaciones
- Rotación periódica de claves
- Cumplimiento PCI DSS 3.2.1+

## 📝 Notas

1. El KCV siempre se devuelve en MAYÚSCULAS
2. Los inputs se aceptan en mayúsculas O minúsculas (se normaliza)
3. Los archivos se leen eliminando espacios en blanco al inicio/fin
4. Las excepciones incluyen el mensaje original para debugging
5. No se guardan llaves en memoria después del uso
6. Todas las operaciones son idempotentes
