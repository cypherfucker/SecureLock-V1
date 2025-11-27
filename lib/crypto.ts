// Encryption and decryption utilities using Web Crypto API and OpenPGP

const CHUNK_SIZE = 64 * 1024 * 1024 // 64MB chunks for large file processing

// Password-based encryption using AES-256-GCM
export async function encryptFile(
  file: File,
  secret: string,
  method: "password" | "pgp",
  onProgress?: (progress: number) => void,
): Promise<Blob> {
  if (method === "password") {
    return encryptFileWithPassword(file, secret, onProgress)
  } else {
    return encryptFileWithPGP(file, secret, onProgress)
  }
}

export async function decryptFile(
  file: File,
  secret: string,
  method: "password" | "pgp",
  onProgress?: (progress: number) => void,
): Promise<{ blob: Blob; fileName: string }> {
  if (method === "password") {
    return decryptFileWithPassword(file, secret, onProgress)
  } else {
    return decryptFileWithPGP(file, secret, onProgress)
  }
}

async function encryptFileWithPassword(
  file: File,
  password: string,
  onProgress?: (progress: number) => void,
): Promise<Blob> {
  // Generate a random salt
  const salt = crypto.getRandomValues(new Uint8Array(16))

  // Generate a random IV
  const iv = crypto.getRandomValues(new Uint8Array(12))

  // Derive key from password using PBKDF2
  const keyMaterial = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, [
    "deriveBits",
    "deriveKey",
  ])

  const key = await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: 100000,
      hash: "SHA-256",
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"],
  )

  // Prepare file metadata
  const metadata = {
    name: file.name,
    type: file.type,
    size: file.size,
  }
  const metadataBytes = new TextEncoder().encode(JSON.stringify(metadata))
  const metadataLength = new Uint32Array([metadataBytes.length])

  // Process file in chunks
  const chunks: Uint8Array[] = []
  let offset = 0

  while (offset < file.size) {
    const chunk = file.slice(offset, offset + CHUNK_SIZE)
    const chunkData = await chunk.arrayBuffer()

    // Encrypt chunk
    const encryptedChunk = await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, key, chunkData)

    chunks.push(new Uint8Array(encryptedChunk))
    offset += CHUNK_SIZE

    // Report progress
    const progress = Math.min(Math.round((offset / file.size) * 100), 100)
    onProgress?.(progress)
  }

  // Combine all encrypted chunks
  const totalSize =
    metadataLength.byteLength +
    metadataBytes.length +
    salt.length +
    iv.length +
    chunks.reduce((acc, chunk) => acc + chunk.length, 0)
  const result = new Uint8Array(totalSize)

  let position = 0

  // Write metadata length (4 bytes)
  result.set(new Uint8Array(metadataLength.buffer), position)
  position += metadataLength.byteLength

  // Write metadata
  result.set(metadataBytes, position)
  position += metadataBytes.length

  // Write salt (16 bytes)
  result.set(salt, position)
  position += salt.length

  // Write IV (12 bytes)
  result.set(iv, position)
  position += iv.length

  // Write encrypted data
  for (const chunk of chunks) {
    result.set(chunk, position)
    position += chunk.length
  }

  return new Blob([result], { type: "application/octet-stream" })
}

async function decryptFileWithPassword(
  file: File,
  password: string,
  onProgress?: (progress: number) => void,
): Promise<{ blob: Blob; fileName: string }> {
  const data = await file.arrayBuffer()
  const dataView = new Uint8Array(data)

  if (data.byteLength < 32) {
    throw new Error("INVALID_FILE_FORMAT")
  }

  let position = 0

  try {
    // Read metadata length
    const metadataLength = new Uint32Array(data.slice(position, position + 4))[0]
    position += 4

    if (metadataLength > 10000 || metadataLength < 10) {
      throw new Error("INVALID_FILE_FORMAT")
    }

    // Read metadata
    const metadataBytes = dataView.slice(position, position + metadataLength)

    let metadata
    try {
      metadata = JSON.parse(new TextDecoder().decode(metadataBytes))
      if (!metadata.name || typeof metadata.name !== "string") {
        throw new Error("INVALID_FILE_FORMAT")
      }
    } catch (e) {
      throw new Error("INVALID_FILE_FORMAT")
    }

    position += metadataLength

    // Read salt
    const salt = dataView.slice(position, position + 16)
    position += 16

    // Read IV
    const iv = dataView.slice(position, position + 12)
    position += 12

    // Read encrypted data
    const encryptedData = dataView.slice(position)

    // Derive key from password
    const keyMaterial = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, [
      "deriveBits",
      "deriveKey",
    ])

    const key = await crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: salt,
        iterations: 100000,
        hash: "SHA-256",
      },
      keyMaterial,
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"],
    )

    // Decrypt data
    const decryptedData = await crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, key, encryptedData)

    onProgress?.(100)

    return {
      blob: new Blob([decryptedData], { type: metadata.type }),
      fileName: metadata.name,
    }
  } catch (error) {
    if (error instanceof Error && error.message === "INVALID_FILE_FORMAT") {
      throw new Error("INVALID_FILE_FORMAT")
    }
    throw new Error("Decryption failed. Please check your password.")
  }
}

async function encryptFileWithPGP(
  file: File,
  publicKeyArmored: string,
  onProgress?: (progress: number) => void,
): Promise<Blob> {
  // Dynamically import OpenPGP
  const openpgp = await import("openpgp")

  try {
    // Read public key
    const publicKey = await openpgp.readKey({ armoredKey: publicKeyArmored })

    // Prepare file metadata
    const metadata = {
      name: file.name,
      type: file.type,
      size: file.size,
    }
    const metadataStr = JSON.stringify(metadata)

    // Read file data
    const fileData = await file.arrayBuffer()

    // Combine metadata and file data
    const metadataBytes = new TextEncoder().encode(metadataStr)
    const metadataLength = new Uint32Array([metadataBytes.length])
    const combined = new Uint8Array(metadataLength.byteLength + metadataBytes.length + fileData.byteLength)

    combined.set(new Uint8Array(metadataLength.buffer), 0)
    combined.set(metadataBytes, metadataLength.byteLength)
    combined.set(new Uint8Array(fileData), metadataLength.byteLength + metadataBytes.length)

    onProgress?.(50)

    // Encrypt
    const encrypted = await openpgp.encrypt({
      message: await openpgp.createMessage({ binary: combined }),
      encryptionKeys: publicKey,
      format: "binary",
    })

    onProgress?.(100)

    return new Blob([encrypted as Uint8Array], { type: "application/octet-stream" })
  } catch (error) {
    throw new Error("PGP encryption failed: " + (error instanceof Error ? error.message : "Unknown error"))
  }
}

async function decryptFileWithPGP(
  file: File,
  privateKeyArmored: string,
  onProgress?: (progress: number) => void,
): Promise<{ blob: Blob; fileName: string }> {
  // Dynamically import OpenPGP
  const openpgp = await import("openpgp")

  try {
    // Read private key
    const privateKey = await openpgp.readPrivateKey({ armoredKey: privateKeyArmored })

    // Read encrypted data
    const encryptedData = await file.arrayBuffer()

    onProgress?.(30)

    // Decrypt
    const message = await openpgp.readMessage({
      binaryMessage: new Uint8Array(encryptedData),
    })

    const { data: decrypted } = await openpgp.decrypt({
      message,
      decryptionKeys: privateKey,
      format: "binary",
    })

    onProgress?.(80)

    // Extract metadata and file data
    const decryptedData = decrypted as Uint8Array

    if (decryptedData.length < 4) {
      throw new Error("INVALID_FILE_FORMAT")
    }

    const metadataLength = new Uint32Array(decryptedData.slice(0, 4).buffer)[0]

    if (metadataLength > 10000 || metadataLength < 10 || metadataLength > decryptedData.length) {
      throw new Error("INVALID_FILE_FORMAT")
    }

    const metadataBytes = decryptedData.slice(4, 4 + metadataLength)

    let metadata
    try {
      metadata = JSON.parse(new TextDecoder().decode(metadataBytes))
      if (!metadata.name || typeof metadata.name !== "string") {
        throw new Error("INVALID_FILE_FORMAT")
      }
    } catch (e) {
      throw new Error("INVALID_FILE_FORMAT")
    }

    const fileData = decryptedData.slice(4 + metadataLength)

    onProgress?.(100)

    return {
      blob: new Blob([fileData], { type: metadata.type }),
      fileName: metadata.name,
    }
  } catch (error) {
    if (error instanceof Error && error.message === "INVALID_FILE_FORMAT") {
      throw new Error("INVALID_FILE_FORMAT")
    }
    throw new Error("PGP decryption failed: " + (error instanceof Error ? error.message : "Unknown error"))
  }
}
