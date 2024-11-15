from Crypto.Cipher import DES, AES, DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

# Función para ajustar la clave según el tamaño requerido
def ajustar_clave(clave, tamaño):
    clave_bytes = clave.encode("utf-8")
    if len(clave_bytes) < tamaño:
        clave_bytes += get_random_bytes(tamaño - len(clave_bytes))
    elif len(clave_bytes) > tamaño:
        clave_bytes = clave_bytes[:tamaño]
    print(f"Clave ajustada: {clave_bytes.decode('utf-8', errors='ignore')}")
    return clave_bytes

# Funciones de cifrado y descifrado para DES
def cifrar_DES(texto, clave, iv):
    cipher = DES.new(clave, DES.MODE_CBC, iv)
    texto_cifrado = cipher.encrypt(pad(texto.encode("utf-8"), DES.block_size))
    return base64.b64encode(texto_cifrado).decode("utf-8")

def descifrar_DES(texto_cifrado, clave, iv):
    cipher = DES.new(clave, DES.MODE_CBC, iv)
    texto_cifrado_bytes = base64.b64decode(texto_cifrado.encode("utf-8"))
    texto_descifrado = unpad(cipher.decrypt(texto_cifrado_bytes), DES.block_size)
    return texto_descifrado.decode("utf-8")

# Funciones de cifrado y descifrado para AES-256
def cifrar_AES(texto, clave, iv):
    cipher = AES.new(clave, AES.MODE_CBC, iv)
    texto_cifrado = cipher.encrypt(pad(texto.encode("utf-8"), AES.block_size))
    return base64.b64encode(texto_cifrado).decode("utf-8")

def descifrar_AES(texto_cifrado, clave, iv):
    cipher = AES.new(clave, AES.MODE_CBC, iv)
    texto_cifrado_bytes = base64.b64decode(texto_cifrado.encode("utf-8"))
    texto_descifrado = unpad(cipher.decrypt(texto_cifrado_bytes), AES.block_size)
    return texto_descifrado.decode("utf-8")

# Funciones de cifrado y descifrado para 3DES
def cifrar_3DES(texto, clave, iv):
    cipher = DES3.new(clave, DES3.MODE_CBC, iv)
    texto_cifrado = cipher.encrypt(pad(texto.encode("utf-8"), DES3.block_size))
    return base64.b64encode(texto_cifrado).decode("utf-8")

def descifrar_3DES(texto_cifrado, clave, iv):
    cipher = DES3.new(clave, DES3.MODE_CBC, iv)
    texto_cifrado_bytes = base64.b64decode(texto_cifrado.encode("utf-8"))
    texto_descifrado = unpad(cipher.decrypt(texto_cifrado_bytes), DES3.block_size)
    return texto_descifrado.decode("utf-8")

# Función principal
def main():
    algoritmo = input("Seleccione el algoritmo (DES, AES, 3DES): ").strip().upper()
    clave = input("Ingrese la clave en texto: ").strip()
    iv_texto = input("Ingrese el vector de inicialización (IV): ").strip()

    # Convertimos el IV a bytes
    iv = iv_texto.encode("utf-8")
    
    # Configuramos el tamaño de clave según el algoritmo
    if algoritmo == "DES":
        clave = ajustar_clave(clave, 8)
        texto = input("Ingrese el texto a cifrar: ").strip()
        texto_cifrado = cifrar_DES(texto, clave, iv)
        print("Texto cifrado:", texto_cifrado)
        print("Texto descifrado:", descifrar_DES(texto_cifrado, clave, iv))

    elif algoritmo == "AES":
        clave = ajustar_clave(clave, 32)
        iv = iv[:16]  # AES requiere un IV de 16 bytes
        texto = input("Ingrese el texto a cifrar: ").strip()
        texto_cifrado = cifrar_AES(texto, clave, iv)
        print("Texto cifrado:", texto_cifrado)
        print("Texto descifrado:", descifrar_AES(texto_cifrado, clave, iv))

    elif algoritmo == "3DES":
        clave = ajustar_clave(clave, 24)
        texto = input("Ingrese el texto a cifrar: ").strip()
        texto_cifrado = cifrar_3DES(texto, clave, iv)
        print("Texto cifrado:", texto_cifrado)
        print("Texto descifrado:", descifrar_3DES(texto_cifrado, clave, iv))

    else:
        print("Algoritmo no soportado.")

if __name__ == "__main__":
    main()
