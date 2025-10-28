
/***********************************************************************************
                                                                                  
  Copyright (C) 2024 Luis Cobian, CobianSoft.                                
  All rights reserved.                                                            
                                                                                  
  http://www.cobiansoft.com                                                       
  cobian@cobiansoft.com                                                           
                                                                                  
  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <https://www.gnu.org/licenses/>                                              
                                                                                  
***********************************************************************************/


// Ignore Spelling: ENCRYPTEDHELLO

using Cobian.Locker.Cryptography;
using System;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;


namespace Cobian.Locker
{
    /// <summary>
    /// A delegate to 
    /// </summary>
    /// <param name="source">The source file</param>
    /// <param name="progress">The progress</param>
    public delegate void FileProgressDel(string source, int progress);

    /// <summary>
    /// Cryptographic functions
    /// </summary>
    internal static class Crypto
    {
        /// <summary>
        /// A string that identifies an encrypted string
        /// </summary>
        public const string ENCRYPTEDHELLO = "«COB»";

        private const int saltSize = 20;
        private const int pseudoRandomBitsKey = 32;

        private const int sizePad = 10;

        private const char zeroChar = '0';

        private const int passwordIterations = 100000;

        /// <summary>
        /// Encrypt a string using the given password
        /// </summary>
        /// <param name="inString">The string to encrypt</param>
        /// <param name="password">The password to use</param>
        /// <returns>The encrypted string</returns>
        public static string EncryptString(string inString, string password)
        {
            if (string.IsNullOrWhiteSpace(password))
                throw new ArgumentNullException(nameof(password), Strings.ErrEmptyPassword);

            if (inString == null)
                throw new ArgumentNullException(nameof(inString), Strings.ErrEmptyInputPassword);

            using RandomNumberGenerator random = RandomNumberGenerator.Create();

            // Convert the plain text string to a byte array
            byte[] plaintextBytes = Encoding.Unicode.GetBytes(inString);

            byte[] salt = new byte[saltSize];

            random.GetBytes(salt);

            // Derive a new password using the PBKDF2 algorithm and a random salt

            using Rfc2898DeriveBytes passwordBytes = new(password, salt, passwordIterations, HashAlgorithmName.SHA512);
            // Use the password to encrypt the plain text
            using Aes encryptor = Aes.Create();

            encryptor.Padding = PaddingMode.PKCS7;
            encryptor.Mode = CipherMode.CBC;

            encryptor.Key = passwordBytes.GetBytes(pseudoRandomBitsKey);

            using MemoryStream ms = new();
            using (CryptoStream cs = new(ms, encryptor.CreateEncryptor(), CryptoStreamMode.Write))
            {
                cs.Write(plaintextBytes, 0, plaintextBytes.Length);
                cs.FlushFinalBlock();
            }

            string saltStr = Convert.ToBase64String(salt);
            string iv = Convert.ToBase64String(encryptor.IV);

            string lengthSalt = saltStr.Length.ToString(CultureInfo.InvariantCulture).PadLeft(sizePad, zeroChar);
            string lengthIV = iv.Length.ToString(CultureInfo.InvariantCulture).PadLeft(sizePad, zeroChar);

            return ENCRYPTEDHELLO + lengthSalt + saltStr + lengthIV + iv + Convert.ToBase64String(ms.ToArray());
        }

        /// <summary>
        /// Decrypt a string using the given password
        /// </summary>
        /// <param name="inString">The string to decrypt</param>
        /// <param name="password">The password to use</param>
        /// <param name="error"> In case of an error, the error type is passed here</param>
        /// <returns>The decrypted string or null if the decryption fails. Throws an exception when it's not cryptografical.</returns>
        public static string? DecryptString(string inString, string password, out CryptoError error)
        {
            error = CryptoError.None;

            if (string.IsNullOrWhiteSpace(password))
            {
                error = CryptoError.EmptyPassword;
                return null;
            }

            if (inString == null)
            {
                error = CryptoError.BadInput;
                return null;
            }

            if (inString.IndexOf(ENCRYPTEDHELLO, StringComparison.Ordinal) != 0)
            {
                error = CryptoError.UnknownEncryptionMethod;
                return null;
            }

            try
            {
                int lengthSalt = Convert.ToInt32(inString.Substring(ENCRYPTEDHELLO.Length, sizePad), CultureInfo.InvariantCulture);
                int lengthIV = Convert.ToInt32(inString.Substring(ENCRYPTEDHELLO.Length + sizePad + lengthSalt, sizePad), CultureInfo.InvariantCulture);

                string saltStr = inString.Substring(ENCRYPTEDHELLO.Length + sizePad, lengthSalt);
                string iv = inString.Substring(ENCRYPTEDHELLO.Length + 2 * sizePad + lengthSalt, lengthIV);

                //Delete the headers
                inString = inString[(ENCRYPTEDHELLO.Length + 2 * sizePad + lengthSalt + lengthIV)..];

                byte[] encryptedBytes = Convert.FromBase64String(inString);
                byte[] salt = Convert.FromBase64String(saltStr);

                using Rfc2898DeriveBytes passwordBytes = new(password, salt, passwordIterations, HashAlgorithmName.SHA512);
                // Use the password to decrypt the encrypted string
                using Aes encryptor = Aes.Create();
                encryptor.Padding = PaddingMode.PKCS7;
                encryptor.Mode = CipherMode.CBC;

                encryptor.Key = passwordBytes.GetBytes(pseudoRandomBitsKey);
                encryptor.IV = Convert.FromBase64String(iv);

                using MemoryStream ms = new();
                using (CryptoStream cs = new(ms, encryptor.CreateDecryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(encryptedBytes, 0, encryptedBytes.Length);
                    cs.FlushFinalBlock();
                }
                return Encoding.Unicode.GetString(ms.ToArray());
            }
            catch (FormatException)
            {
                error = CryptoError.BadHeader;
                return null;
            }
            catch (CryptographicException)
            {
                error = CryptoError.BadPasswordOrCorruptedString;
                return null;
            }
            catch (Exception)
            {
                error = CryptoError.UnknownError;
                return null;
            }
        }

        /// <summary>
        /// Work always in big-endian (v2 only)
        /// </summary>
        /// <param name="array"></param>
        /// <param name="valueIsLittleEndian"></param>
        /// <returns></returns>
        private static byte[] EnsureBigEndian(byte[] array, bool valueIsLittleEndian)
        {
            if (valueIsLittleEndian)
            {
                Array.Reverse(array); // Reverse to convert to Big-Endian
                return array;
            }
            else
                return array;
        }


        /// <summary>
        /// Create and save a pair of keys. Raises exceptions
        /// </summary>
        /// <param name="publicFn">The name of the public key</param>
        /// <param name="privateFn">The name of the private key</param>
        /// <param name="password">Some password (or none) to protect the private key</param>
        /// <param name="size">The size of the key</param>
        public static void CreateKeyPair(string publicFn, string privateFn, string? password, AsymmetricKeySize size)
        {
            using RSA rsa = RSA.Create((int)size);

            var pub = rsa.ExportRSAPublicKey();
            var pri = rsa.ExportRSAPrivateKey();

            SaveKey(false, publicFn, pub, null, (int)size);
            SaveKey(true, privateFn, pri, password, (int)size);
        }

        /// <summary>
        /// Encrypt a file. Raises exceptions
        /// </summary>
        /// <param name="method">The method to use</param>
        /// <param name="source">The source file</param>
        /// <param name="destination">The destination file</param>
        /// <param name="key">A key (when using asymmetric methods)</param>
        /// <param name="progress">Some callback for progress</param>
        /// <param name="password">The password for encryption for symmetric methods</param>
        public static void EncryptFile(EncryptionMethod method, string source, string destination,
            string? key, string? password, FileProgressDel? progress)
        {
            if (string.IsNullOrEmpty(source))
                throw new ArgumentNullException(nameof(source));

            if (string.IsNullOrEmpty(destination))
                throw new ArgumentNullException(nameof(destination));

            if (method == EncryptionMethod.RSA)
            {
                if (string.IsNullOrEmpty(key))
                    throw new ArgumentNullException(nameof(key));
            }
            else
            {
                if (string.IsNullOrEmpty(password))
                    throw new ArgumentNullException(nameof(password));
            }

            progress?.Invoke(source, 0);

#pragma warning disable CS8604 // Possible null reference argument.
            if (method == EncryptionMethod.RSA)
                EncryptFileAsymmetric(source, destination, key, password, progress);
            else

                EncryptFileSymmetric(method, source, destination, password, progress);
#pragma warning restore CS8604 // Possible null reference argument.
        }

        /// <summary>
        /// Check if the given file is an encrypted file .
        /// If the encryption is Aes, it will return AES128 regardless of its true size
        /// </summary>
        /// <param name="fileName">The name of the file</param>
        /// <returns>The type of the file</returns>
        public static EncryptionMethod IsEncrypted(string fileName)
        {

            try
            {
                using FileStream fs = new(fileName, FileMode.Open, FileAccess.Read);
                byte[] buffer = new byte[sizeof(long)];
                fs.Read(buffer, 0, sizeof(long));
                long header = BitConverter.ToInt64(EnsureBigEndian(buffer, BitConverter.IsLittleEndian));

                EncryptionMethod result;

                if (header == Constants.CobAesFlagV2)
                {
                    result = EncryptionMethod.AES128;
                }
                else
                    if (header == Constants.CobRsaFlagV2)
                {
                    result = EncryptionMethod.RSA;
                }
                else
                    result = EncryptionMethod.UnknownMethod;

                fs.Close();

                return result;
            }
            catch
            {
                return EncryptionMethod.UnknownMethod;
            }
        }


        /// <summary>
        /// Decrypts a file. Raises exceptions
        /// </summary>
        /// <param name="source">The encrypted file</param>
        /// <param name="destination">Decrypt to...</param>
        /// <param name="key">The key for asymmetric operations</param>
        /// <param name="password">The password</param>
        /// <param name="progress">Callback</param>
        public static void DecryptFile(string source, string destination, string? key, string? password, FileProgressDel? progress)
        {

            if (string.IsNullOrEmpty(source))
                throw new ArgumentNullException(nameof(source));

            if (string.IsNullOrEmpty(destination))
                throw new ArgumentNullException(nameof(destination));

            using FileStream fs = new(source, FileMode.Open, FileAccess.Read);
            byte[] buffer = new byte[sizeof(long)];

            fs.Read(buffer, 0, sizeof(long));

            long header = BitConverter.ToInt64(EnsureBigEndian(buffer, BitConverter.IsLittleEndian));

            fs.Position = 0;

            if (header == Constants.CobAesFlagV2)
            {
                if (string.IsNullOrEmpty(password))
                    throw new ArgumentNullException(nameof(password));

                DecryptFileSymmetric(fs, source, destination, password, progress);
            }
            else
                if (header == Constants.CobRsaFlagV2)
            {
                if (string.IsNullOrEmpty(key))
                    throw new ArgumentNullException(nameof(key));

                DecryptFileAsymmetric(fs, source, destination, key, password, progress);
            }
            else
                throw new CryptographicException(Strings.ErrBadEncryptionHeader);

            fs.Close();
        }

        private static void DecryptFileSymmetric([NotNull] FileStream sf, [NotNull] string source,
                    [NotNull] string destination, [NotNull] string password,
                FileProgressDel? progress)
        {

            using FileStream df = new(destination, FileMode.Create, FileAccess.ReadWrite);

            byte[] bufferLong = new byte[sizeof(long)];
            byte[] bufferInt = new byte[sizeof(int)];
            int read = 0;

            read = sf.Read(bufferLong, 0, sizeof(long));

            if (read != sizeof(long))
            {
                throw new CryptographicException(Strings.ErrCorruptedFile);
            }

            long flag = BitConverter.ToInt64(EnsureBigEndian(bufferLong, BitConverter.IsLittleEndian));

            // read the encryption flag
            if (flag != Constants.CobAesFlagV2)
                throw new CryptographicException(Strings.ErrBadEncryptionHeader);

            long originalSize = 0;
            int keybytes = 0, saltLength = 0, ivLength = 0;

            // read the size of the original file
            read = sf.Read(bufferLong, 0, sizeof(long));

            if (read != sizeof(long))
            {
                throw new CryptographicException(Strings.ErrCorruptedFile);
            }

            originalSize = BitConverter.ToInt64(EnsureBigEndian(bufferLong, BitConverter.IsLittleEndian));

            //Read the size of the key
            read = sf.Read(bufferInt, 0, sizeof(int));

            if (read != sizeof(int))
            {
                throw new CryptographicException(Strings.ErrCorruptedFile);
            }

            keybytes = BitConverter.ToInt32(EnsureBigEndian(bufferInt, BitConverter.IsLittleEndian));

            //Read the length of the salt
            read = sf.Read(bufferInt, 0, sizeof(int));

            if (read != sizeof(int))
            {
                throw new CryptographicException(Strings.ErrCorruptedFile);
            }

            saltLength = BitConverter.ToInt32(EnsureBigEndian( bufferInt, BitConverter.IsLittleEndian));

            //Read the salt
            byte[] salt = new byte[saltLength];

            read = sf.Read(salt, 0, saltLength);

            if (read != saltLength)
            {
                throw new CryptographicException(Strings.ErrCorruptedFile);
            }

            //Read the size of the iv
            read = sf.Read(bufferInt, 0, sizeof(int));

            if (read != sizeof(int))
            {
                throw new CryptographicException(Strings.ErrCorruptedFile);
            }

            ivLength = BitConverter.ToInt32(EnsureBigEndian(bufferInt, BitConverter.IsLittleEndian));

            byte[] iv = new byte[ivLength];

            //read the iv
            read = sf.Read(iv, 0, ivLength);

            if (read != ivLength)
            {
                throw new CryptographicException(Strings.ErrCorruptedFile);
            }

            using MemoryStream ms = new();

            using Aes aes = Aes.Create();
            aes.Padding = PaddingMode.PKCS7;
            aes.Mode = CipherMode.CBC;
            using Rfc2898DeriveBytes passwordBytes = new(password, salt, passwordIterations, HashAlgorithmName.SHA512);
            // Use the password to decrypt the encrypted string
            aes.Key = passwordBytes.GetBytes(keybytes);

            aes.IV = iv;
            using CryptoStream cs = new(df, aes.CreateDecryptor(), CryptoStreamMode.Write);
            using CryptoStream csPh = new(ms, aes.CreateDecryptor(), CryptoStreamMode.Write);

            // read the size of the password flag
            read = sf.Read(bufferLong, 0, sizeof(long));

            if (read != sizeof(long))
            {
                throw new CryptographicException(Strings.ErrCorruptedFile);
            }

            long paswordFlagSize = BitConverter.ToInt64(EnsureBigEndian(bufferLong, BitConverter.IsLittleEndian));

            byte[] passwordFlagBytes = new byte[paswordFlagSize];

            read = sf.Read(passwordFlagBytes, 0, (int)paswordFlagSize);

            if (read != paswordFlagSize)
            {
                throw new CryptographicException(Strings.ErrCorruptedFile);
            }

            try
            {
                csPh.Write(passwordFlagBytes, 0, passwordFlagBytes.Length);
                csPh.FlushFinalBlock();
            }
            catch (CryptographicException e)
            {
                throw new CryptographicException(Strings.ErrBadPasswordOrCorruptedFile, e);
            }

            string passwordFlag = Encoding.Unicode.GetString(ms.ToArray());

            csPh.Close();
            ms.Close();

            if (!passwordFlag.Equals(Constants.Llave, StringComparison.Ordinal))
            {
                throw new CryptographicException(Strings.ErrBadPasswordOrCorruptedFile);
            }

            //Password OK. Now proceed


            long total = 0;
            int percent = 0, lastPercent = 0;
            long encryptedTotal = sf.Length - sf.Position;

            byte[] buffer = new byte[Constants.BufferSizeAES];

            do
            {
                read = sf.Read(buffer, 0, buffer.Length);

                if (read == 0)
                    break;

                cs.Write(buffer, 0, read);

                total += read;

                if (encryptedTotal != 0)
                {
                    percent = (int)((double)total / encryptedTotal * 100);
                    if (percent != lastPercent)
                    {
                        progress?.Invoke(source, percent);
                        lastPercent = percent;
                    }
                }

            }
            while (read > 0);

            cs.FlushFinalBlock();

            if (originalSize != df.Length)
                throw new CryptographicException(Strings.ErrCorruptedFile);

            cs.Flush();
            cs.Close();
            sf.Close();

            df.Close();

        }

        private static void DecryptFileAsymmetric([NotNull] FileStream sf, [NotNull] string source, [NotNull] string destination, [NotNull] string key,
            string? password, FileProgressDel? progress)
        {
            using FileStream df = new(destination, FileMode.Create, FileAccess.Write);

            byte[] bufferLong = new byte[sizeof(long)];

            int read = 0;

            // read the flag
            read = sf.Read(bufferLong, 0, bufferLong.Length);

            if (read != sizeof(long))
            {
                throw new CryptographicException(Strings.ErrBadEncryptionHeader);
            }

            long header = BitConverter.ToInt64(EnsureBigEndian(bufferLong, BitConverter.IsLittleEndian));

            if (header != Constants.CobRsaFlagV2)
            {
                throw new CryptographicException(Strings.ErrBadEncryptionHeader);
            }

            //read the original size

            read = sf.Read(bufferLong, 0, bufferLong.Length);

            if (read != sizeof(long))
            {
                throw new CryptographicException(Strings.ErrBadEncryptionHeader);
            }

            long originalSize = BitConverter.ToInt64(EnsureBigEndian(bufferLong, BitConverter.IsLittleEndian));

            long current = 0;
            int lastPercent = 0, percent = 0;

            long total = sf.Length - sf.Position;

            using RSA rsa = GetKey(key, true, password);

            byte[] bufferInt = new byte[sizeof(int)];

            do
            {
                read = sf.Read(bufferInt, 0, bufferInt.Length);

                if (read == 0)
                    break;

                if (read != sizeof(int))
                {
                    throw new CryptographicException(Strings.ErrBadKeyOrCorruptedFile);
                }

                current += read;

                // Read the size of the encrypted chunk
                int encryptedChunkSize = BitConverter.ToInt32(EnsureBigEndian(bufferInt, BitConverter.IsLittleEndian));

                byte[] encryptedChunk = new byte[encryptedChunkSize];

                // Read the encrypted chunk
                read = sf.Read(encryptedChunk, 0, encryptedChunk.Length);
                if (read != encryptedChunkSize)
                {
                    throw new CryptographicException(Strings.ErrBadKeyOrCorruptedFile);
                }

                current += read;

                // Decrypt the chunk using RSA

                try
                {

                    byte[] decryptedData = rsa.Decrypt(encryptedChunk, RSAEncryptionPadding.OaepSHA256);
                    // Write the decrypted data to the output stream
                    df.Write(decryptedData, 0, decryptedData.Length);
                }
                catch (CryptographicException)
                {
                    throw new CryptographicException(Strings.ErrBadKeyOrCorruptedFile);
                }

                if (total > 0)
                {
                    percent = (int)((double)current / total * 100);
                    if (percent != lastPercent)
                    {
                        progress?.Invoke(source, percent);
                        lastPercent = percent;
                    }
                }

            }
            while (read > 0);

            df.Flush();
            long endSize = df.Length;


            if (originalSize != df.Length)
            {
                throw new CryptographicException(Strings.ErrBadKeyOrCorruptedFile);
            }

            df.Close();
            sf.Close();
        }

        private static void EncryptFileSymmetric(EncryptionMethod method, [NotNull] string source, [NotNull] string destination,
            [NotNull] string password, FileProgressDel? progress)
        {
            using FileStream sf = new(source, FileMode.Open, FileAccess.Read);
            using FileStream df = new(destination, FileMode.Create, FileAccess.ReadWrite);
            using Aes aes = Aes.Create();

            int keySize;

            switch (method)
            {
                case EncryptionMethod.AES128:
                    {
                        keySize = Constants.Size128Bytes;
                        break;
                    }
                case EncryptionMethod.AES192:
                    {
                        keySize = Constants.Size192Bytes;
                        break;
                    }
                case EncryptionMethod.AES256:
                    {
                        keySize = Constants.Size256Bytes;
                        break;
                    }
                default:
                    throw new CryptographicException(Strings.ErrBadKeySize);
            }

            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            using RandomNumberGenerator random = RandomNumberGenerator.Create();

            byte[] salt = new byte[saltSize];
            random.GetBytes(salt);

            // Derive a new password using the PBKDF2 algorithm and a random salt

            using Rfc2898DeriveBytes passwordBytes = new(password, salt, passwordIterations, HashAlgorithmName.SHA512);
            // Use the password to encrypt the file

            aes.Key = passwordBytes.GetBytes(keySize);

            long inputLength = sf.Length;

            //Write the type of file
            df.Write(EnsureBigEndian(BitConverter.GetBytes(Constants.CobAesFlagV2), BitConverter.IsLittleEndian));
            //Write the original size of the source
            df.Write(EnsureBigEndian(BitConverter.GetBytes(inputLength), BitConverter.IsLittleEndian));
            //write the key size in bytes
            df.Write(EnsureBigEndian(BitConverter.GetBytes(keySize), BitConverter.IsLittleEndian));
            //write the length of the salt
            df.Write(EnsureBigEndian(BitConverter.GetBytes(salt.Length), BitConverter.IsLittleEndian));
            //write the salt
            df.Write(salt);
            //write the length of the iv
            df.Write(EnsureBigEndian(BitConverter.GetBytes(aes.IV.Length), BitConverter.IsLittleEndian));
            //write the iv
            df.Write(aes.IV);

            byte[] buffer = new byte[Constants.BufferSizeAES];
            var pb = Encoding.Unicode.GetBytes(Constants.Llave);

            using CryptoStream cryptoStream = new(df, aes.CreateEncryptor(), CryptoStreamMode.Write);

            //used for the password header
            //Encrypt it and store it.
            using MemoryStream msPH = new();
            using CryptoStream cryptoStreamPH = new(msPH, aes.CreateEncryptor(), CryptoStreamMode.Write);
            cryptoStreamPH.Write(pb, 0, pb.Length);
            cryptoStreamPH.FlushFinalBlock();

            //write the encrypted password length
            df.Write(EnsureBigEndian(BitConverter.GetBytes(msPH.Length), BitConverter.IsLittleEndian));
            //write the encrypted password
            msPH.Position = 0;
            msPH.CopyTo(df);
            cryptoStreamPH.Close();
            msPH.Close();

            //now, encrypt the sf

            int read = 0;
            long total = 0;
            int percent = 0, lastPercent = 0;

            do
            {
                read = sf.Read(buffer);
                total += read;
                cryptoStream.Write(buffer, 0, read);

                if (inputLength != 0)
                    percent = (int)((double)total / inputLength) * 100;

                if (percent != lastPercent)
                {
                    progress?.Invoke(source, percent);
                    lastPercent = percent;
                }

            }
            while (total < inputLength);

            cryptoStream.FlushFinalBlock();
            cryptoStream.Flush();
            cryptoStream.Close();
            df.Close();
            sf.Close();
        }

        private static void EncryptFileAsymmetric([NotNull] string source, [NotNull] string destination,
            [NotNull] string key, string? password, FileProgressDel? progress)
        {

            using FileStream sf = new(source, FileMode.Open, FileAccess.Read);
            using FileStream df = new(destination, FileMode.Create, FileAccess.ReadWrite);

            using var rsa = GetKey(key, false, password);

            // RSA block size limit is determined by key size and padding mode
            int rsaBlockSize = rsa.KeySize / 8 - 2 * (Constants.RsaHashLength / 8) - 2;

            long sourceSize = sf.Length;

            // add the flag
            df.Write(EnsureBigEndian(BitConverter.GetBytes(Constants.CobRsaFlagV2), BitConverter.IsLittleEndian));
            //Write the original size of the source
            df.Write(EnsureBigEndian(BitConverter.GetBytes(sourceSize), BitConverter.IsLittleEndian));

            byte[] buffer = new byte[rsaBlockSize];
            int bytesRead;

            long current = 0;

            int percent = 0, lastPercent = 0;


            while ((bytesRead = sf.Read(buffer, 0, buffer.Length)) > 0)
            {
                // Encrypt the chunk using RSA
                byte[] encryptedData = rsa.Encrypt(buffer.AsSpan(0, bytesRead).ToArray(), RSAEncryptionPadding.OaepSHA256);

                // Write the encrypted chunk size followed by the encrypted data
                df.Write(EnsureBigEndian(BitConverter.GetBytes(encryptedData.Length), BitConverter.IsLittleEndian), 0, sizeof(int));
                df.Write(encryptedData, 0, encryptedData.Length);

                current += bytesRead;

                if (sourceSize != 0)
                {
                    percent = (int)((double)current / sourceSize * 100);

                    if (percent != lastPercent)
                    {
                        progress?.Invoke(source, percent);
                        lastPercent = percent;
                    }
                }
            }

            df.Flush();
            df.Close();
            sf.Close();
        }

        /// <summary>
        /// Gets a Rsa key from file. Raises exceptions
        /// </summary>
        /// <param name="fileName">The file name</param>
        /// <param name="isPrivate">Is this a private key</param>
        /// <param name="password">Some password (if any)</param>
        /// <returns>A key or null</returns>
        private static RSA GetKey(string fileName, bool isPrivate, string? password)
        {
            var key = LoadKey(fileName, password, out bool isPublic);

            if (isPublic == isPrivate)
            {
                throw new CryptographicException(Strings.ErrWrongKeyType);
            }

            if (key == null)
            {
                throw new CryptographicException(Strings.ErrorBadKey);
            }

            RSA rsa = RSA.Create();
            if (isPrivate)
                rsa.ImportRSAPrivateKey(key.AsSpan(), out _);
            else
                rsa.ImportRSAPublicKey(key.AsSpan(), out _);

            return rsa;
        }

        /// <summary>
        /// Loads a key from file 
        /// </summary>
        /// <param name="fileName">The name of the file</param>
        /// <param name="password">The password</param>
        /// <param name="isPublic">Is the key public</param>
        /// <returns>Null if failed</returns>
        private static byte[]? LoadKey(string fileName, string? password, out bool isPublic)
        {
            isPublic = false;

            using FileStream stream = new(fileName, FileMode.Open, FileAccess.Read);
            using TextReader reader = new StreamReader(stream, Encoding.UTF8);

            string? s;
            StringBuilder sb = new();

            do
            {
                s = reader.ReadLine();

                if (s != null)
                {

                    if (s.Equals(Constants.KeyHeader, StringComparison.Ordinal))
                        continue;

                    if (s.Equals(Constants.KeyHeaderV2, StringComparison.Ordinal))
                        continue;

                    if (s.Equals(Constants.KeySubHeaderPub, StringComparison.Ordinal))
                    {
                        isPublic = true;
                        continue;
                    }

                    if (s.Equals(Constants.KeySubHeaderPrE, StringComparison.Ordinal))
                        continue;

                    if (s.Equals(Constants.KeySubHeaderPrv, StringComparison.Ordinal))
                        continue;

                    if (s.Equals(Constants.KeyFooter, StringComparison.Ordinal))
                        continue;

                    if (s.IndexOf(Constants.KeyFooterSizeH, StringComparison.Ordinal) == 0)
                        continue;

                    sb.Append(s);

                }
                else
                {
                    string? result = sb.ToString();
                    if (password != null)
                    {
                        result = DecryptString(result, password, out CryptoError err);
                        switch (err)
                        {
                            case CryptoError.None:
                                break;
                            case CryptoError.EmptyPassword:
                                {
                                    throw new CryptographicException(Strings.ErrEmptyPassword);
                                }
                            case CryptoError.UnknownEncryptionMethod:
                                {
                                    throw new CryptographicException(Strings.ErrUnknownEncryptionMethod);
                                }
                            case CryptoError.BadHeader:
                                {
                                    throw new CryptographicException(Strings.ErrBadEncryptionHeader);
                                }
                            case CryptoError.BadPasswordOrCorruptedString:
                                {
                                    throw new CryptographicException(Strings.ErrBadPasswordOrCorruptedString);
                                }
                            case CryptoError.BadInput:
                                {
                                    throw new CryptographicException(Strings.ErrBadInput);
                                }
                            case CryptoError.UnknownError:
                                {
                                    throw new CryptographicException(Strings.ErrUnknownError);
                                }
                            default:
                                break;
                        }
                    }

                    if (result == null)
                        throw new CryptographicException(Strings.ErrUnknownError);

                    return Convert.FromBase64String(result);

                }

            }
            while (true);
        }

        /// <summary>
        /// Save a key
        /// </summary>
        /// <param name="isPrivate">Is this key private</param>
        /// <param name="fileName">The name of the file to store the key in</param>
        /// <param name="content">The content of the key</param>
        /// <param name="password">Encrypt if not null</param>
        /// <param name="keySize">The key size</param>
        private static void SaveKey(bool isPrivate, string fileName, byte[] content, string? password, int keySize)
        {
            // The format of the key:
            // Header **** RSA key, Cobian Format ****
            // Sub- header: **** Public key  ****
            // or
            // **** Private key ****
            // or 
            // **** Private key, encrypted ****
            // Content, trunked at 80 in size
            // Content, trunked at 80 in size
            // ...
            // Content, trunked at 80 in size
            // Footer **** End of the key ****
            // The file can have any encoding because it's pure ascii

            //2025-09-29, version 2, compatible with Cobian Encryptor

            using FileStream stream = new(fileName, FileMode.Create, FileAccess.ReadWrite);
            using TextWriter writer = new StreamWriter(stream, Encoding.UTF8);

            writer.WriteLine(Constants.KeyHeaderV2);
            writer.WriteLine(string.Format(CultureInfo.InvariantCulture,
                Constants.KeyFooterSize, keySize.ToString(CultureInfo.InvariantCulture)).PadRight(Constants.KeyWidth, Constants.FooterChar));
            writer.WriteLine(isPrivate ?
                string.IsNullOrEmpty(password) ? Constants.KeySubHeaderPrv : Constants.KeySubHeaderPrE :
                 Constants.KeySubHeaderPub);

            bool encrypt = false;

            if (isPrivate && !string.IsNullOrEmpty(password))
                encrypt = true;

            string result = Convert.ToBase64String(content);

            if (encrypt)
#pragma warning disable CS8604 // Possible null reference argument.Already checked in "encrypt"
                result = EncryptString(result, password);
#pragma warning restore CS8604 // Possible null reference argument.

            int index = 0;

            do
            {
                if (index >= result.Length)
                    break;

                writer.WriteLine(result.AsSpan(index, Math.Min(Constants.KeyWidth, result.Length - index)));
                index += Constants.KeyWidth;
            }
            while (true);

            writer.WriteLine(Constants.KeyFooter);
            writer.Flush();
            writer.Close();

        }
    }
}
