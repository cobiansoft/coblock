
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

using Cobian.Locker.Cryptography;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;

namespace Cobian.Locker
{
    /// <summary>
    /// Parses the command line arguments
    /// </summary>
    internal class ArgumentParser
    {
        private readonly List<string> args =[];

        /// <summary>
        /// This is the verb of the command.
        /// The verb can be null,
        /// Create key,
        /// Encrypt,
        /// Decrypt,
        /// Create global default settings settings
        /// Create local default settings
        /// show version
        /// show help
        /// </summary>
        public Verb Command { get; private set; } = Verb.Help;

        /// <summary>
        /// Process the files recursively. -r
        /// </summary>
        public bool Recursive { get; private set; }

        /// <summary>
        /// Laconic mode
        /// </summary>
        public bool Laconic { get; private set; }

        /// <summary>
        /// Process hidden files. -h
        /// </summary>
        public bool Hidden { get; private set; }

        /// <summary>
        /// True to set Yes to all questions. -y
        /// </summary>
        public bool Yes {get; set; }

        /// <summary>
        /// Delete source after encryption
        /// </summary>
        public bool DeleteAfterEncryption { get; private set; }

        /// <summary>
        /// Use a non-default encryption method. Use as -m:"the method"
        /// </summary>
        public EncryptionMethod? Method { get; set; }

        /// <summary>
        /// The key size when creating keys. Use -s:2048 for example
        /// </summary>
        public AsymmetricKeySize? KeySize { get; set; }

        /// <summary>
        /// The key to use. Must be used as -k:"the key"
        /// </summary>
        public string? Key { get; set; }

        /// <summary>
        /// Used only when reading from settings
        /// </summary>
        public string? KeyForEncryption { get; private set; }

        /// <summary>
        /// Used only when reading from settings
        /// </summary>
        public string? KeyForDecryption { get; private set; }
        /// <summary>
        /// The password used to encrypt/decrypt OR to open a private key if it is encrypted
        /// Must be used as: -p:"the password"
        /// </summary>
        public string? Password { get; set; }

        /// <summary>
        /// The source is used for: what to encrypt or decrypt OR for the key to create
        /// </summary>
        public string? Source { get; set; }

        /// <summary>
        /// The destination is used for: what to encrypt TO or decrypt TO
        /// </summary>
        public string? Destination { get; set; }


        /// <summary>
        /// The constructor 
        /// </summary>
        /// <param name="args">The command line arguments</param>
        public ArgumentParser(string[] args) 
        { 
            this.args = [];
            foreach (string arg in args) 
            {
                if (!CanStack(arg)) 
                {
                    this.args.Add(arg);
                }
                else
                {
                    Unstack(arg);
                }
            }

            LoadSettings();

            Parse();
        }

        /// <summary>
        /// Short arguments can "stack". For example -la = -l -a
        /// </summary>
        /// <param name="arg">The argument to analyze</param>
        /// <returns>True if this is a short argument </returns>
        private static bool CanStack(string arg)
        {
            if (arg.Length < 3)
                return false;

            return (arg[0].Equals(Constants.CharFlag)) && (!arg[2].Equals(Constants.CharSeparator));
        }

        /// <summary>
        ///  Short arguments can "stack". For example -la = -l -a
        ///  Unstack if needed
        /// </summary>
        /// <param name="stack">The arguments</param>
        private void Unstack(string stack) 
        { 
            if (stack[0].Equals(Constants.CharFlag)) 
            {
                stack = stack[1..];
                foreach (char s in stack) 
                {
                    args.Add(string.Concat(Constants.CharFlag, s));
                }
            }
        }

        /// <summary>
        /// Get the name and path of the config file
        /// </summary>
        /// <param name="path">returns the path without file name</param>
        /// <returns>The name of the file without path</returns>
        public static string GetConfigFile(out string? path)
        {
            string? folder, pn, fn, author;

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                folder = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
                pn = Custom.AppNameLong;
                author = Custom.Author;
                fn = Path.ChangeExtension(pn, Constants.ExtIni);
            }
            else
            {
                folder = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                pn = Constants.HiddenL + Custom.AppName;
                author = Constants.HiddenL +  Custom.Author;
                fn = Path.ChangeExtension(pn, Constants.ExtConfig);
            }

            path = Path.Combine(folder, author, pn);
            return fn;
        }

        /// <summary>
        /// Load the default settings if those exist.
        /// The priority is:
        /// 1- Global settings file (Lower priority)
        /// 2- Local settings file for the current user (medium priority)
        /// 3- The command (highest priority)
        /// </summary>
        private void LoadSettings()
        {
            string fn = GetConfigFile(out string? path);

            if (!string.IsNullOrEmpty(path))
            {
                string fullPath = Path.Combine(path, fn);

                if (File.Exists(fullPath))
                {
                    try
                    {
                        LoadDefaults(fullPath);
                    }
                    catch
                    {
                        //Ignore
                    }
                }
            }
        }

        /// <summary>
        /// Decode the first argument
        /// </summary>
        /// <param name="verb">Theverb</param>
        /// <returns>Null if the verb is wrong</returns>
        private static Verb DecodeVerb(string verb)
        {
            switch (verb)
            {
                case var b when b.Equals(Constants.VerbHelp, StringComparison.Ordinal):
                case var bs when bs.Equals(Constants.VerbHelpShort, StringComparison.Ordinal):
                    {
                        return Verb.Help;
                    }
                case var b when b.Equals(Constants.VerbVersion, StringComparison.Ordinal):
                case var bs when bs.Equals(Constants.VerbVersionShort, StringComparison.Ordinal):
                    {
                        return Verb.Version;
                    }
                case var b when b.Equals(Constants.VerbCreateKeys, StringComparison.Ordinal):
                case var bs when bs.Equals(Constants.VerbCreateKeysShort, StringComparison.Ordinal):
                    {
                        return Verb.CreateKeys;
                    }
                case var b when b.Equals(Constants.VerbEncrypt, StringComparison.Ordinal):
                case var bs when bs.Equals(Constants.VerbEncryptShort, StringComparison.Ordinal):
                    {
                        return Verb.Encrypt;
                    }
                case var b when b.Equals(Constants.VerbEncryptpassword, StringComparison.Ordinal):
                case var bs when bs.Equals(Constants.VerbEncryptpasswordShort, StringComparison.Ordinal):
                    {
                        return Verb.EncryptPassword;
                    }
                case var b when b.Equals(Constants.VerbDecrypt, StringComparison.Ordinal):
                case var bs when bs.Equals(Constants.VerbDecryptShort, StringComparison.Ordinal):
                    {
                        return Verb.Decrypt;
                    }
                case var b when b.Equals(Constants.VerbConfig, StringComparison.Ordinal):
                case var bs when bs.Equals(Constants.VerbConfigShort, StringComparison.Ordinal):
                    {
                        return Verb.Config;
                    }
                case var b when b.Equals(Constants.VerbAbout, StringComparison.Ordinal):
                case var bs when bs.Equals(Constants.VerbAboutShort, StringComparison.Ordinal):
                    {
                        return Verb.About;
                    }
                default: 
                    {
                        return Verb.NoVerb;
                    }
            }
        }

        /// <summary>
        /// Get the predicate of a flag
        /// </summary>
        /// <param name="flag">The predicate is everything after :, for example in -k:"key name"</param>
        /// <returns>The predicate</returns>
        private static string? GetPredicate(string  flag)
        {
            if (string.IsNullOrEmpty(flag))
                return null;

            if (!flag.Contains(Constants.CharSeparator, StringComparison.Ordinal))
                return null;

            var s = flag.Remove(0, flag.IndexOf(Constants.CharSeparator, StringComparison.Ordinal) + 1);

            if (string.IsNullOrEmpty(s))
                return null;

            if (s.Length < 2)
                return s;

            //if the predicate contains spaces, it will be surrounded by quotes

            if ((s[0] == Constants.CharQuotes) && (s[^1] == Constants.CharQuotes))
            {
                s = s.Remove(s.Length - 1, 1).Remove(0, 1);
                s = s.Replace(Constants.DoubleQuotes, Constants.Quotes, StringComparison.Ordinal);
            }

            return s;
        }

        /// <summary>
        /// Returns the whole flag for simple flags -h or the flag part of a complex one -k:text => -k
        /// </summary>
        /// <param name="flag">The flag</param>
        /// <returns>The pure flag</returns>
        private static string? DepureFlag(string flag)
        {
            if (string.IsNullOrWhiteSpace(flag))
            {
                return null;
            }

            if (flag.Contains(Constants.CharSeparator, StringComparison.Ordinal))
            {
                return flag[..flag.IndexOf(Constants.CharSeparator, StringComparison.Ordinal)];
            }
            else
            {
                return flag;
            }
        }

        /// <summary>
        /// Get a encryption method
        /// </summary>
        /// <param name="method"></param>
        /// <returns></returns>
        private static EncryptionMethod GetEncryptionMethod(string? method)
        {
            if (string.IsNullOrWhiteSpace(method))
                return EncryptionMethod.UnknownMethod;

            switch (method)
            {
                case var b when b.Equals(Constants.PredicateAES128, StringComparison.OrdinalIgnoreCase):
                    {
                        return EncryptionMethod.AES128;
                    }
                case var b when b.Equals(Constants.PredicateAES192, StringComparison.OrdinalIgnoreCase):
                    {
                        return EncryptionMethod.AES192;
                    }
                case var b when b.Equals(Constants.PredicateAES256, StringComparison.OrdinalIgnoreCase):
                    {
                        return EncryptionMethod.AES256;
                    }
                case var b when b.Equals(Constants.PredicateRSA, StringComparison.OrdinalIgnoreCase):
                    {
                        return EncryptionMethod.RSA;
                    }
                default:
                    return EncryptionMethod.UnknownMethod;
            }
        }

        /// <summary>
        /// Get the key size
        /// </summary>
        /// <param name="size">The size of the key</param>
        /// <returns>The key size</returns>
        private static AsymmetricKeySize GetKeySize(string? size)
        {
            if (string.IsNullOrWhiteSpace(size))
                return AsymmetricKeySize.UnsupportedSize;

            switch (size)
            {
                case var b when b.Equals(Constants.PredicateSize1024, StringComparison.OrdinalIgnoreCase):
                    {
                        return AsymmetricKeySize.Size1024;
                    }
                case var b when b.Equals(Constants.PredicateSize2048, StringComparison.OrdinalIgnoreCase):
                    {
                        return AsymmetricKeySize.Size2048;
                    }
                case var b when b.Equals(Constants.PredicateSize3072, StringComparison.OrdinalIgnoreCase):
                    {
                        return AsymmetricKeySize.Size3072;
                    }
                case var b when b.Equals(Constants.PredicateSize4096, StringComparison.OrdinalIgnoreCase):
                    {
                        return AsymmetricKeySize.Size4096;
                    }
                case var b when b.Equals(Constants.PredicateSize8192, StringComparison.OrdinalIgnoreCase):
                    {
                        return AsymmetricKeySize.Size8192;
                    }
                default:
                    return AsymmetricKeySize.UnsupportedSize;
            }
        }

        /// <summary>
        /// Decode a flag
        /// </summary>
        /// <param name="flag">The flag</param>
        private void DecodeFlag(string flag)
        {
            string? pureFlag = DepureFlag(flag);
            
            if (string.IsNullOrEmpty(pureFlag))
            {
                return;
            }           


            switch (pureFlag)
            {
                case var b when b.Equals(Constants.FlagRecursive, StringComparison.Ordinal):
                    {
                        Recursive = true;
                        break;
                    }

                case var b when b.Equals(Constants.FlagDelete, StringComparison.Ordinal):
                    {
                        DeleteAfterEncryption = true;
                        break;
                    }

                case var b when b.Equals(Constants.FlagHidden, StringComparison.Ordinal):
                    {
                        Hidden = true;
                        break;
                    }

                case var b when b.Equals(Constants.FlagLaconic, StringComparison.Ordinal):
                    {
                        Laconic = true;
                        break;
                    }

                case var b when b.Equals(Constants.FlagYes, StringComparison.Ordinal):
                    {
                        Yes = true;
                        break;
                    }

                case var b when b.Equals(Constants.FlagEncryptionMethod, StringComparison.Ordinal):
                    {
                        Method = GetEncryptionMethod(GetPredicate(flag));
                        break;
                    }
                case var b when b.Equals(Constants.FlagKeySize, StringComparison.Ordinal):
                    {
                        KeySize = GetKeySize(GetPredicate(flag));
                        break;
                    }
                case var b when b.Equals(Constants.FlagPassword, StringComparison.Ordinal):
                    {
                        Password = GetPredicate(flag);
                        break;
                    }
                case var b when b.Equals(Constants.FlagKey, StringComparison.Ordinal):
                    {
                        Key = GetPredicate(flag);
                        break;
                    }
                default:
                    break;
            }
        }

        /// <summary>
        /// Is the argument a flag?
        /// </summary>
        /// <param name="arg">The string to analyze</param>
        /// <returns>True if its a flag</returns>
        private static bool IsFlag(string arg)
        {
            if (string.IsNullOrWhiteSpace(arg)) 
                return false;

            return arg[0].Equals(Constants.CharFlag);
        }

        /// <summary>
        /// Parse the arguments
        /// </summary>
        private void Parse() 
        { 
            if (args.Count == 0)
            {
                Command = Verb.Help;
                return;
            }

            Command = DecodeVerb(args[0]);
            
            if (Command == Verb.NoVerb)
            {
                return;
            }

            if (args.Count == 1)
                return;

            int counter = 0;

            for (int i = 1; i < args.Count; i++) 
            {
                if (!string.IsNullOrEmpty(args[i]))
                {
                    if (IsFlag(args[i]))
                        DecodeFlag(args[i]);
                    else
                    {
                        switch (counter)
                        {
                            case 0:
                                {
                                    Source = args[i];
                                    counter++;
                                    break;
                                }
                            case 1:
                                {
                                    Destination = args[i];
                                    counter++;
                                    break;
                                }
                            default:
                                return;
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Generate a comment
        /// </summary>
        /// <param name="text">The text to comment</param>
        /// <returns>A comment for the default file</returns>
        private static string GenerateComment(string text)
        {
            return String.Concat(Constants.Comment, text);
        }

        /// <summary>
        /// Returns true if the line is empty or a comment
        /// </summary>
        /// <param name="text">The text to check</param>
        /// <returns>False if this is real INI data</returns>
        private static bool IsCommentOrEmpty(string? text)
        {
            if (string.IsNullOrWhiteSpace(text)) 
                return true;

            return text.TrimStart().IndexOf(Constants.Comment, StringComparison.Ordinal) == 0;
        }
        
        /// <summary>
        /// Generate a key/value pair
        /// </summary>
        /// <param name="key">The key</param>
        /// <param name="value">The value</param>
        /// <returns>A key/value pair</returns>
        private static string EncodeIniPair(string key, string? value)
        {
            return String.Concat(key, Constants.KeyValueSeparator, value);
        }

        /// <summary>
        /// Save the defaults to the given path. Can throw exceptions
        /// </summary>
        /// <param name="path">The path (with file name)</param>
        public static void SaveDefaults(string path)
        {
            using FileStream stream = new(path, FileMode.Create, FileAccess.ReadWrite);
            using TextWriter writer = new StreamWriter(stream, System.Text.Encoding.UTF8);

            List<string> dict = [];
            dict.Add(GenerateComment(string.Format(CultureInfo.CurrentCulture, Strings.CommentHeader, Custom.AppNameLong)));
            dict.Add(string.Empty);
            dict.Add(GenerateComment(Strings.CommentHidden));
            dict.Add(EncodeIniPair(Constants.IniHidden, string.Empty));
            dict.Add(string.Empty);
            dict.Add(GenerateComment(Strings.CommentLaconic));
            dict.Add(EncodeIniPair(Constants.IniLaconic, string.Empty));
            dict.Add(string.Empty);
            dict.Add(GenerateComment(Strings.CommentKeyEncryption));
            dict.Add(EncodeIniPair(Constants.IniKeyEncryption, string.Empty));
            dict.Add(string.Empty);
            dict.Add(GenerateComment(Strings.CommentKeyDecryption));
            dict.Add(EncodeIniPair(Constants.IniKeyDecryption, string.Empty));
            dict.Add(string.Empty);
            dict.Add(GenerateComment(Strings.CommentEncryptionMethod));
            dict.Add(EncodeIniPair(Constants.IniEncryptionMethod, string.Empty));
            dict.Add(string.Empty);
            dict.Add(GenerateComment(Strings.CommentPassword));
            dict.Add(GenerateComment(Strings.CommentPassword1));
            dict.Add(GenerateComment(Strings.CommentPassword2));
            dict.Add(EncodeIniPair(Constants.IniPassword, string.Empty));
            dict.Add(string.Empty);
            dict.Add(GenerateComment(Strings.CommentRecursive));
            dict.Add(EncodeIniPair(Constants.IniRecursive, string.Empty));
            dict.Add(string.Empty);
            dict.Add(GenerateComment(Strings.CommentKeySize));
            dict.Add(GenerateComment(Strings.CommentKeySize2));
            dict.Add(EncodeIniPair(Constants.IniKeySize, string.Empty));
            dict.Add(string.Empty);
            dict.Add(GenerateComment(Strings.CommentYes));
            dict.Add(EncodeIniPair(Constants.IniAlwaysYes, string.Empty));
            dict.Add(string.Empty);
            dict.Add(GenerateComment(Strings.CommentDelete));
            dict.Add(EncodeIniPair(Constants.IniDelete, string.Empty));

            foreach (var s in dict)
                writer.WriteLine(s);

            writer.Flush();
            writer.Close();
        }

        /// <summary>
        /// Decodes an ini par
        /// </summary>
        /// <param name="encoded">The encoded string</param>
        /// <param name="value">The value or null if empty</param>
        /// <returns>The key or null if no "=" is found</returns>
        private static string? DecodeIniPair(string encoded, out string? value)
        {
            value = null;
            if (string.IsNullOrWhiteSpace(encoded))
            {
                return null;
            }

            encoded = encoded.Trim();

            int index = encoded.IndexOf(Constants.KeyValueSeparator, StringComparison.Ordinal);

            if (index <= 1) 
            {
                return null;
            }

            if (index < encoded.Length - 1)
                value = encoded[(index + 1)..].Trim(); ;

            return encoded[..index].Trim();
        }

       
        /// <summary>
        /// Convert a string to a Encryption Method
        /// </summary>
        /// <param name="method">The string</param>
        /// <returns>The method</returns>
        private static EncryptionMethod EncryptionMethodFromString(string method)
        {
            return method switch
            {
                var b when b.Equals(Constants.PredicateAES128, StringComparison.OrdinalIgnoreCase) => EncryptionMethod.AES128,
                var b when b.Equals(Constants.PredicateAES192, StringComparison.OrdinalIgnoreCase) => EncryptionMethod.AES192,
                var b when b.Equals(Constants.PredicateAES256, StringComparison.OrdinalIgnoreCase) => EncryptionMethod.AES256,
                var b when b.Equals(Constants.PredicateRSA, StringComparison.OrdinalIgnoreCase) => EncryptionMethod.RSA,
                _ => EncryptionMethod.AES256,
            };
        }

        /// <summary>
        /// Apply the value to a property
        /// </summary>
        /// <param name="key">The key</param>
        /// <param name="value">The value</param>
        private void ApplyValue(string key, string? value)
        {
            switch (key) 
            {
                case var b when b.Equals(Constants.IniHidden, StringComparison.Ordinal):
                    {
                        if (!string.IsNullOrEmpty(value))
                        {
                            try
                            {
                                Hidden = Convert.ToBoolean(value, CultureInfo.InvariantCulture);
                            }
                            catch (FormatException)
                            {
                                Hidden = false;
                            }
                        }
                        break;
                    }
                case var b when b.Equals(Constants.IniLaconic, StringComparison.Ordinal):
                    {
                        if (!string.IsNullOrEmpty(value))
                        {
                            try
                            {
                                Laconic = Convert.ToBoolean(value, CultureInfo.InvariantCulture);
                            }
                            catch (FormatException)
                            {
                                Laconic = false;
                            }
                        }
                        break;
                    }
                case var b when b.Equals(Constants.IniKeyEncryption, StringComparison.Ordinal):
                    {
                        KeyForEncryption = value;
                        break;
                    }
                case var b when b.Equals(Constants.IniKeyDecryption, StringComparison.Ordinal):
                    {
                        KeyForDecryption = value;
                        break;
                    }
                case var b when b.Equals(Constants.IniEncryptionMethod, StringComparison.Ordinal):
                    {
                        if (!string.IsNullOrEmpty(value))
                        {
                            Method = EncryptionMethodFromString(value);
                        }
                        break;
                    }
                case var b when b.Equals(Constants.IniPassword, StringComparison.Ordinal):
                    {
                        if (!string.IsNullOrEmpty(value))
                        {
                            var s = Crypto.DecryptString(value, Custom.Guid, out CryptoError error);
                            if (error == CryptoError.None)
                                Password = s;
                            else
                                Password = null;
                        }
                        break;
                    }
                case var b when b.Equals(Constants.IniRecursive, StringComparison.Ordinal):
                    {
                        if (!string.IsNullOrEmpty(value))
                        {
                            try
                            {
                                Recursive = Convert.ToBoolean(value, CultureInfo.InvariantCulture);
                            }
                            catch (FormatException)
                            {
                                Recursive = false;
                            }
                        }
                        break;
                    }
                case var b when b.Equals(Constants.IniKeySize, StringComparison.Ordinal):
                    {
                        if (!string.IsNullOrEmpty(value))
                        {
                            try
                            {                                
                                KeySize = (AsymmetricKeySize)Convert.ToInt32(value, CultureInfo.InvariantCulture);
                            }
                            catch (FormatException)
                            {
                                KeySize = AsymmetricKeySize.Size2048;
                            }
                            catch (OverflowException)
                            {
                                KeySize = AsymmetricKeySize.Size2048;
                            }
                        }
                        break;
                    }
                case var b when b.Equals(Constants.IniAlwaysYes, StringComparison.Ordinal):
                    {
                        if (!string.IsNullOrEmpty(value))
                        {
                            try
                            {
                                Yes = Convert.ToBoolean(value, CultureInfo.InvariantCulture);
                            }
                            catch (FormatException)
                            {
                                Yes = false;
                            }
                        }
                        break;
                    }
                case var b when b.Equals(Constants.IniDelete, StringComparison.Ordinal):
                    {
                        if (!string.IsNullOrEmpty(value))
                        {
                            try
                            {
                                DeleteAfterEncryption = Convert.ToBoolean(value, CultureInfo.InvariantCulture);
                            }
                            catch (FormatException)
                            {
                                DeleteAfterEncryption = false;
                            }
                        }
                        break;
                    }
                default:
                    break;
            }
        }

        /// <summary>
        /// Load the defaults from the given file. Can throw exceptions
        /// </summary>
        /// <param name="path">The file to load</param>
        private void LoadDefaults(string path)
        {
            using FileStream stream = new(path, FileMode.Open, FileAccess.Read);
            using TextReader reader = new StreamReader(stream, System.Text.Encoding.UTF8);

            string? s;

            do
            {
                s = reader.ReadLine();

                if (IsCommentOrEmpty(s))
                    continue;

                string? key = DecodeIniPair(s??string.Empty, out string? value);

                if (key != null)
                    ApplyValue(key, value);  

            }
            while (s != null);
        }
    }
}
