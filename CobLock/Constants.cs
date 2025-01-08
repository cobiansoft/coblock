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

namespace Cobian.Locker
{
    /// <summary>
    /// Constants used by the porgram
    /// </summary>
    internal static class Constants
    {
        /// <summary>
        /// The program version
        /// </summary>
        public static string Version = "1.0.0";


        //results

        /// <summary>
        /// No errors. Closed gratefully
        /// </summary>
        public const int ExitOk = 0;

        /// <summary>
        /// No arguments passed
        /// </summary>
        public const int ExitNoArguments = 1;
        public const int ExitNoConfigDir = 2;
        public const int ExitAccessDenied = 3;
        public const int ExitConfigError = 4;
        public const int ExitOperationAbortedByTheUser = 5;
        public const int ExitPasswordsDontMatch = 6;
        public const int ExitBadFileName = 7;
        public const int ExitNoParser = 8;
        public const int ExitKeySavingError = 9;
        public const int ExitNoSource = 10;
        public const int ExitNoDestination = 11;
        public const int ExitWeakPassword = 12;
        public const int ExitUnknownSource = 13;
        public const int ExitCryptoError = 14;
        public const int ExitNotSupported = 15;
        public const int ExitIOError = 16;
        public const int ExitSecurityError = 17;
        public const int ExitUnexpectedError = 
            18;
        public const int ExitSeveralErrors = 19;
        public const int ExitUnknownEncryptionMethod = 20;

        public const string DirCommonAppDataL = "/etc";

        public const string HiddenL = ".";

        public const string AllFiles = "*";

        public const char AnyChars = '*';
        public const char OneCharChar = '?';

        public const string ExtIni = ".ini";
        public const string ExtConfig = ".config";
        public const string ExtPrivate = ".prv";
        public const string ExtPublic = ".pub";
        public const string ExtEncrypted = ".enc";

        public const string StringYes = "y";
        public const string StringNo = "n";
        public const string StringAll = "a";
        public const string StringCancel = "c";

        public const string Comment = "//";
        public const string KeyValueSeparator = "=";

        public const string DoubleBack = "\b \b";
        public const string ConsoleMask = "*";

        public const char Space = ' ';

        public const int RsaHashLength = 256;

        // arguments

        public const string VerbHelp = "help";
        public const string VerbHelpShort = "h";
        public const string VerbVersion = "version";
        public const string VerbVersionShort = "v";
        public const string VerbCreateKeys = "create-keys";
        public const string VerbCreateKeysShort = "ck";
        public const string VerbEncrypt = "encrypt";
        public const string VerbEncryptShort = "e";
        public const string VerbDecrypt = "decrypt";
        public const string VerbDecryptShort = "d";
        public const string VerbConfig = "config";
        public const string VerbConfigShort = "c";
        public const string VerbAbout = "about";
        public const string VerbAboutShort = "a";
        public const string VerbEncryptpassword = "encrypt-password";
        public const string VerbEncryptpasswordShort = "ep";

        public const string FlagHidden = "-h";
        public const string FlagKey = "-k";
        public const string FlagEncryptionMethod = "-m";
        public const string FlagPassword = "-p";
        public const string FlagRecursive = "-r";
        public const string FlagKeySize = "-s";
        public const string FlagYes = "-y";
        public const string FlagDelete = "-d";
        public const string FlagLaconic = "-l";
        public const string FlagDebug = "-!";

   
        public const string IniHidden = "HiddenFiles";
        public const string IniKeyEncryption = "EncryptionKey";
        public const string IniKeyDecryption = "DecryptionKey";
        public const string IniEncryptionMethod = "EncryptionMethod";
        public const string IniPassword = "Password";
        public const string IniRecursive = "ProcessSubdirectories";
        public const string IniKeySize = "KeySize";
        public const string IniAlwaysYes = "YesToAll";
        public const string IniDelete = "DeleteSource";
        public const string IniLaconic = "LaconicMode";

        public const char CharFlag = '-';
        public const char CharSeparator = ':';
        public const char CharQuotes = '"';
        public const char CharHidden = '.';

        public const long CobAesFlag = 0xC0BAE5F0F0F0F;
        public const long CobRsaFlag = 0xC0B78AF0F0F0F;

        public const string DoubleQuotes = "\"\"";
        public const string Quotes = "\"";

        public const string Llave = "{666AC66B-D2CD-48BC-AECE-074A58EB29A2}";

        public const string PredicateAES128 = "aes128";
        public const string PredicateAES192 = "aes192";
        public const string PredicateAES256 = "aes256";
        public const string PredicateRSA = "rsa";

        public const int Size128Bytes = 16;
        public const int Size192Bytes = 24;
        public const int Size256Bytes = 32;

        public const string PredicateSize1024 = "1024";
        public const string PredicateSize2048 = "2048";
        public const string PredicateSize3072 = "3072";
        public const string PredicateSize4096 = "4096";
        public const string PredicateSize8192 = "8192";

        public const int BufferSize = 32768;

        public const int KeyWidth = 80;
        public const string KeyHeader =       "************************     RSA key, Cobian Format     ************************";
        public const string KeySubHeaderPub = "************************           Public key           ************************";
        public const string KeySubHeaderPrv = "************************           Private key          ************************";
        public const string KeySubHeaderPrE = "************************     Private key (encrypted)    ************************";
        public const string KeyFooter =       "************************          End of the key        ************************";
    }
}
