
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
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.IO;
using System.Security;
using System.Security.Cryptography;

namespace Cobian.Locker
{
    internal class Program
    {
        private static ArgumentParser? parser;

        /// <summary>
        /// This is the entry point of the program
        /// </summary>
        /// <param name="args">The command line arguments</param>
        static int Main(string[] args)
        {
            Console.OutputEncoding = System.Text.Encoding.UTF8;

            parser = new ArgumentParser(args);

#if DEBUG
            if (parser.Debug)
            {
                Console.WriteLine(Strings.MsgDebug);
                _= Console.ReadLine();
            }
#endif

            return AnalyzeArguments(args);
        }


        /// <summary>
        /// Show a catastrophic error
        /// </summary>
        /// <param name="error">The error to show</param>
        private static void ShowError(string error)
        {
            Console.WriteLine(string.Format(CultureInfo.CurrentCulture, Strings.ErrorHeader, error));
        }

        /// <summary>
        /// Show the about information
        /// </summary>
        private static void ShowAbout()
        {
            Console.WriteLine(string.Format(CultureInfo.CurrentCulture,
                Strings.AboutProgram, Custom.AppNameLong, Custom.AppName));
            Console.WriteLine(string.Format(CultureInfo.CurrentCulture,
                Strings.AboutVersion, Custom.Version));
            Console.WriteLine(string.Format(CultureInfo.CurrentCulture,
                Strings.AboutCopyright, Custom.Years, Custom.AuthorLong));
            Console.WriteLine(Strings.AboutAllRights);
            Console.WriteLine(Custom.Web);
            Console.WriteLine(Custom.Mail);
        }

        /// <summary>
        /// Show the help file
        /// </summary>
        private static void ShowHelp()
        {
            Console.WriteLine(string.Format(CultureInfo.CurrentCulture,
                Strings.HelpIntro, Custom.AppNameLong, Custom.AppName));
            Console.WriteLine();

            Console.WriteLine(string.Format(CultureInfo.CurrentCulture,
                Strings.AboutVersion, Custom.Version));
            Console.WriteLine();

            Console.WriteLine(Strings.HelpUsage);
            Console.WriteLine();

            Console.WriteLine(Strings.HelpVerb);
            Console.WriteLine(Strings.HelpVerb1);

            Console.WriteLine();

            Console.WriteLine(Strings.HelpVerbAbout);
            Console.WriteLine(Strings.HelpVerbConfig);
            Console.WriteLine(Strings.HelpVerbCreateKeys);
            Console.WriteLine(Strings.HelpVerbDecrypt);
            Console.WriteLine(Strings.HelpVerbEncrypt);
            Console.WriteLine(Strings.HelpVerbEncryptPassword);
            Console.WriteLine(Strings.HelpVerbHelp);
            Console.WriteLine(Strings.HelpVerbVersion);

            Console.WriteLine();

            Console.WriteLine(Strings.HelpFlags);
            Console.WriteLine(Strings.HelpFlags1);

            Console.WriteLine();

            Console.WriteLine(Strings.HelpFlagDelete);
            Console.WriteLine(Strings.HelpFlagHidden);
            Console.WriteLine(Strings.HelpFlagKey);
            Console.WriteLine(Strings.HelpFlagEncryptionMethod);
            Console.WriteLine(Strings.HelpFlagLaconic);
            Console.WriteLine(Strings.HelpFlagPassword);
            Console.WriteLine(Strings.HelpFlagRecursive);
            Console.WriteLine(Strings.HelpFlagKeySize);
            Console.WriteLine(Strings.HelpFlagYes);

            Console.WriteLine();

            Console.WriteLine(Strings.HelpSource);
            Console.WriteLine(Strings.HelpSource1);

            Console.WriteLine();

            Console.WriteLine(Strings.HelpDestination);
            Console.WriteLine(Strings.HelpDestination1);

        }

        private static ConsoleAnswer AnswerQuestion(string question, bool acceptAll, bool acceptCancel)
        {
            Console.Write(question + Constants.Space);

            string? info;

            do
            {
                info = Console.ReadLine();

                if (info == null)
                    return ConsoleAnswer.Cancel;

                bool ok = ((info.Equals(Constants.StringYes, StringComparison.Ordinal))
                    || (info.Equals(Constants.StringNo, StringComparison.Ordinal)) ||
                    ((info.Equals(Constants.StringAll, StringComparison.Ordinal)) && acceptAll) ||
                    ((info.Equals(Constants.StringCancel, StringComparison.Ordinal)) && acceptCancel));

                if (ok)
                {
                    return info switch
                    {
                        var b when b.Equals(Constants.StringYes, StringComparison.Ordinal) => ConsoleAnswer.Yes,
                        var b when b.Equals(Constants.StringNo, StringComparison.Ordinal) => ConsoleAnswer.No,
                        var b when b.Equals(Constants.StringAll, StringComparison.Ordinal) => ConsoleAnswer.All,
                        var b when b.Equals(Constants.StringCancel, StringComparison.Ordinal) => ConsoleAnswer.Cancel,
                        _ => ConsoleAnswer.Cancel,
                    };
                }
                else
                {
                    Console.WriteLine(Strings.MsgInvalidAnswer);
                    Console.Write(question + Constants.Space);
                }
            }
            while (true);
        }

        private static void ShowSpecialMessage(string msg)
        {
            Console.WriteLine(string.Format(CultureInfo.CurrentCulture, Strings.StrSpecialMessage, msg));
        }

        /// <summary>
        /// Create a configuration file
        /// </summary>
        /// <returns>The result of the operation</returns>
        private static int CreateConfigFile()
        {
            string fn = ArgumentParser.GetConfigFile(out string? path);

            if (string.IsNullOrEmpty(path))
            {
                ShowError(Strings.ErrNoConfigDir);

                return Constants.ExitNoConfigDir;
            }

            if (!Directory.Exists(path))
            {
                try
                {
                    Directory.CreateDirectory(path);
                }
                catch (UnauthorizedAccessException)
                {
                    ShowError(string.Format(CultureInfo.CurrentCulture, Strings.ErrAccessDeniedCD, path));
                    return Constants.ExitAccessDenied;
                }
                catch (Exception ex)
                {
                    ShowError(string.Format(CultureInfo.CurrentCulture, Strings.ErrConfigErrorD, path, ex.Message));
                    return Constants.ExitConfigError;
                }

            }

            string fullPath = Path.Combine(path, fn);

            if (File.Exists(fullPath))
            {
                var response = AnswerQuestion(string.Format(CultureInfo.CurrentCulture,
                    Strings.MsgReplaceConfig, fullPath), false, false);

                if (response != ConsoleAnswer.Yes)
                {
                    ShowSpecialMessage(Strings.MsgAborted);

                    return Constants.ExitOperationAbortedByTheUser;
                }
            }

            try
            {
                ArgumentParser.SaveDefaults(fullPath);

                ShowSpecialMessage(Strings.MsgConfigFileCreated);

                return Constants.ExitOk;
            }
            catch (SecurityException)
            {
                ShowError(string.Format(CultureInfo.CurrentCulture, Strings.ErrAccessDenied, fullPath));
                return Constants.ExitAccessDenied;
            }
            catch (UnauthorizedAccessException)
            {
                ShowError(string.Format(CultureInfo.CurrentCulture, Strings.ErrAccessDenied, fullPath));
                return Constants.ExitAccessDenied;
            }
            catch (Exception ex)
            {
                ShowError(string.Format(CultureInfo.CurrentCulture, Strings.ErrConfigWrite, fullPath, ex.Message));
                return Constants.ExitConfigError;
            }
        }

        /// <summary>
        /// Reads the password from the string, masking it
        /// </summary>
        /// <returns></returns>
        private static string MaskPassword()
        {
            string pwd = string.Empty;

            ConsoleKey key;
            do
            {
                var keyInfo = Console.ReadKey(intercept: true);
                key = keyInfo.Key;

                if (key == ConsoleKey.Backspace && pwd.Length > 0)
                {
                    Console.Write(Constants.DoubleBack);
                    pwd = pwd[0..^1];
                }
                else if (!char.IsControl(keyInfo.KeyChar))
                {
                    Console.Write(Constants.ConsoleMask);
                    pwd += keyInfo.KeyChar;
                }
            } while (key != ConsoleKey.Enter);

            Console.WriteLine();

            return pwd;
        }

        /// <summary>
        /// Encrypt a password
        /// </summary>
        /// <returns>The result of the operation</returns>
        private static int EncryptPassword()
        {
            Console.WriteLine(Strings.MsgEncryptPasswordEnter);

            string pwd = MaskPassword();


            Console.WriteLine(Strings.MsgEncryptPasswordEnterRe);

            string pwdRe = MaskPassword();

            if (!pwd.Equals(pwdRe, StringComparison.Ordinal))
            {
                ShowError(Strings.ErrPasswordsDontMatch);
                return Constants.ExitPasswordsDontMatch;
            }
            else
            {
                string s = Crypto.EncryptString(pwd, Custom.Guid);
                Console.WriteLine();
                Console.WriteLine(s);
                return Constants.ExitOk;
            }
        }

        /// <summary>
        /// Create a key pair
        /// </summary>
        /// <returns>The result of the operation</returns>
        private static int CreateKeyPair()
        {

            if (parser == null)
                return Constants.ExitNoParser;

            Console.WriteLine(Strings.MsgCreateKey);

            string? fn;

            if (string.IsNullOrEmpty(parser.Source))
            {
                Console.Write(Strings.MsgCreateKeyFileName);
                fn = Console.ReadLine();
            }
            else
                fn = parser.Source;

            if (string.IsNullOrEmpty(fn))
            {
                ShowError(Strings.ErrBadFileName);
                return Constants.ExitBadFileName;
            }

            string publicKey = fn;
            string privateKey = fn;

            publicKey += Constants.ExtPublic;
            privateKey += Constants.ExtPrivate;

            if (File.Exists(publicKey) || File.Exists(privateKey))
            {
                var a = AnswerQuestion(Strings.MsgKeyExistsWarning, false, false);

                if (a != ConsoleAnswer.Yes)
                {
                    return Constants.ExitOperationAbortedByTheUser;
                }
            }

            if (parser.KeySize == null)
            {
                Console.WriteLine(Strings.MsgUsingDefaultKeySize);
                parser.KeySize = AsymmetricKeySize.Size2048;
            }

            if (string.IsNullOrEmpty(parser.Password))
            {
                Console.WriteLine(Strings.MsgEnterKeyPassword);
                var pwd = MaskPassword();

                if (!string.IsNullOrEmpty(pwd))
                {
                    Console.WriteLine(Strings.MsgEnterKeyPasswordRe);
                    var pwdRe = MaskPassword();

                    if (!pwd.Equals(pwdRe, StringComparison.Ordinal))
                    {
                        ShowSpecialMessage(Strings.ErrPasswordsDontMatch);
                        return Constants.ExitPasswordsDontMatch;
                    }
                    else
                        parser.Password = pwd;
                }
            }

            try
            {
                Crypto.CreateKeyPair(publicKey, privateKey, parser.Password, parser.KeySize.Value);

                Console.WriteLine(Strings.MsgKeysCreatedSuccessfully);
                Console.WriteLine(Strings.MsgKeysWarning);

                return Constants.ExitOk;
            }
            catch (Exception ex)
            {
                ShowError(string.Format(CultureInfo.CurrentCulture, Strings.ErrCreatingKeyPair, ex.Message));
                return Constants.ExitKeySavingError;
            }
        }


        /// <summary>
        /// Encrypt a file or directory
        /// </summary>
        /// <returns>0 if everything is OK</returns>
        private static int Encrypt()
        {
            if (parser == null)
            {
                Console.WriteLine(Strings.ErrParserNotFound);
                return Constants.ExitNoParser;
            }

            if (string.IsNullOrEmpty(parser.Source))
            {
                Console.WriteLine(Strings.MsgEnterSource);
                parser.Source = Console.ReadLine();
            }

            if (string.IsNullOrEmpty(parser.Source))
            {
                Console.WriteLine(Strings.ErrNoSource);
                return Constants.ExitNoSource;
            }

            if (string.IsNullOrEmpty(parser.Destination))
            {
                Console.WriteLine(Strings.MsgEnterDestination);
                parser.Destination = Console.ReadLine();
            }

            if (string.IsNullOrEmpty(parser.Destination))
            {
                Console.WriteLine(Strings.ErrNoDestination);
                return Constants.ExitNoDestination;
            }

            if (parser.Method == null)
            {
                ShowMessageLaconic(Strings.MsgDefaultMethod);
                parser.Method = EncryptionMethod.AES256;
            }

            if (parser.Method == EncryptionMethod.RSA)
            {
                if (string.IsNullOrEmpty(parser.Key))
                {
                    if (!string.IsNullOrEmpty(parser.KeyForEncryption))
                        parser.Key = parser.KeyForEncryption;
                }

                if (string.IsNullOrEmpty(parser.Key))
                {
                    Console.WriteLine(Strings.MsgEnterPublicKey);
                    parser.Key = Console.ReadLine();
                }

            }
            else
            {
                if (string.IsNullOrEmpty(parser.Password))
                {
                    Console.WriteLine(Strings.MsgEnterPasswordForEncryption);
                    string p = MaskPassword();

                    if (string.IsNullOrEmpty(p))
                    {
                        Console.WriteLine(Strings.ErrEmptyPasswordEnc);
                        return Constants.ExitWeakPassword;
                    }

                    Console.WriteLine(Strings.MsgReEnterPasswordForEncryption);
                    string pp = MaskPassword();

                    if (!pp.Equals(p, StringComparison.Ordinal))
                    {
                        Console.WriteLine(Strings.ErrPasswordsDontMatch);
                        return Constants.ExitPasswordsDontMatch;
                    }

                    parser.Password = p;
                }
            }


            var kind = GetSDType(parser.Source);

            switch (kind)
            {
                case SDType.Unknown:
                    {
                        Console.WriteLine(string.Format(CultureInfo.CurrentCulture, Strings.ErrUnknownSource, parser.Source));
                        return Constants.ExitUnknownSource;
                    }
                case SDType.File:
                    {
                        return EncryptFile();
                    }
                case SDType.Directory:
                    {
                        return EncryptDirectory();
                    }
                case SDType.Mask:
                    {
                        return EncryptMask();
                    }
                default:
                    {
                        Console.WriteLine(string.Format(CultureInfo.CurrentCulture, Strings.ErrUnknownSource, parser.Source));
                        return Constants.ExitUnknownSource;
                    }
            }
        }

        /// <summary>
        /// Show a message respecting the laconic setting
        /// </summary>
        /// <param name="msg">The message to show</param>
        private static void ShowMessageLaconic(string msg)
        {
            bool laconic = parser != null && parser.Laconic;

            if (laconic)
                Console.WriteLine(msg);
        }

        /// <summary>
        /// Decrypt a single file
        /// </summary>
        /// <returns></returns>
        private static int DecryptFile()
        {
            if (parser == null)
                return Constants.ExitNoParser;

            if (string.IsNullOrEmpty(parser.Destination))
            {
                Console.WriteLine(Strings.ErrNoDestination);
                return Constants.ExitNoDestination;
            }

            if (!Directory.Exists(parser.Destination))
            {
                try
                {
                    ShowMessageLaconic(string.Format(CultureInfo.CurrentCulture, Strings.MsgCreatingDirectory, parser.Destination));
                    Directory.CreateDirectory(parser.Destination);

                }
                catch (IOException e)
                {
                    ShowError(string.Format(CultureInfo.CurrentCulture, Strings.ErrIOError, e.Message));
                    return Constants.ExitIOError;
                }
                catch (SecurityException e)
                {
                    ShowError(string.Format(CultureInfo.CurrentCulture, Strings.ErrSecurityException, e.Message));
                    return Constants.ExitSecurityError;
                }
                catch (UnauthorizedAccessException e)
                {
                    ShowError(string.Format(CultureInfo.CurrentCulture, Strings.ErrSecurityException, e.Message));
                    return Constants.ExitSecurityError;
                }
                catch (Exception e)
                {
                    ShowError(string.Format(CultureInfo.CurrentCulture, Strings.ErrUnexpectedError, e.Message));
                    return Constants.ExitUnexpectedError;
                }
            }

            string d = Path.Combine(parser.Destination, Path.GetFileName(parser.Source ?? string.Empty));

            if (Constants.ExtEncrypted.Equals(Path.GetExtension(d), StringComparison.Ordinal))
                d = d[..^Constants.ExtEncrypted.Length];

            var result = DecryptSingleFile(parser.Source ?? string.Empty, d, false, out _);

            if (result == Constants.ExitOk)
                ShowSpecialMessage(string.Format(CultureInfo.CurrentCulture, Strings.MsgSingleFileDecrypted, parser.Source));

            return result;
        }


        /// <summary>
        /// Encrypt a single file
        /// </summary>
        /// <returns>The result of the operation. 0 = no error</returns>
        private static int EncryptFile()
        {
            if (parser == null)
                return Constants.ExitNoParser;

            if (string.IsNullOrEmpty(parser.Destination))
            {
                Console.WriteLine(Strings.ErrNoDestination);
                return Constants.ExitNoDestination;
            }

            if (!Directory.Exists(parser.Destination))
            {
                try
                {
                    ShowMessageLaconic(string.Format(CultureInfo.CurrentCulture, Strings.MsgCreatingDirectory, parser.Destination));
                    Directory.CreateDirectory(parser.Destination);

                }
                catch (IOException e)
                {
                    ShowError(string.Format(CultureInfo.CurrentCulture, Strings.ErrIOError, e.Message));
                    return Constants.ExitIOError;
                }
                catch (SecurityException e)
                {
                    ShowError(string.Format(CultureInfo.CurrentCulture, Strings.ErrSecurityException, e.Message));
                    return Constants.ExitSecurityError;
                }
                catch (UnauthorizedAccessException e)
                {
                    ShowError(string.Format(CultureInfo.CurrentCulture, Strings.ErrSecurityException, e.Message));
                    return Constants.ExitSecurityError;
                }
                catch (Exception e)
                {
                    ShowError(string.Format(CultureInfo.CurrentCulture, Strings.ErrUnexpectedError, e.Message));
                    return Constants.ExitUnexpectedError;
                }
            }

            string d = Path.Combine(parser.Destination, Path.GetFileName(parser.Source ?? string.Empty) + Constants.ExtEncrypted);

            var result = EncryptSingleFile(parser.Source ?? string.Empty, d, false, out _);

            if (result == Constants.ExitOk)
                ShowSpecialMessage(string.Format(CultureInfo.CurrentCulture, Strings.MsgSingleFileEncrypted, parser.Source));

            return result;

        }

        /// <summary>
        /// This is called by the single file operation but also by recursive methods
        /// </summary>
        /// <param name="source">The source</param>
        /// <param name="destination">The destination</param>
        /// <param name="answer">Some answer in case of any questions</param>
        /// <param name="partOfMassOp">Is this operation called as a part of a mass operation?</param>
        /// <returns>The result of the operation</returns>
        private static int DecryptSingleFile([NotNull] string source, [NotNull] string destination, bool partOfMassOp, out ConsoleAnswer answer)
        {
            answer = ConsoleAnswer.Yes;

            if (parser == null)
                return Constants.ExitNoParser;

            var method = Crypto.IsEncrypted(source);

            if (method == EncryptionMethod.UnknownMethod)
            {
                Console.WriteLine(string.Format(CultureInfo.CurrentCulture,
                    Strings.ErrUnknownDecryptionMethod, source));
                return Constants.ExitUnknownEncryptionMethod;
            }

            // now check if the password and key are given

            if (method == EncryptionMethod.RSA)
            {
                if (string.IsNullOrEmpty(parser.Key))
                {
                    Console.WriteLine(Strings.MsgEnterPrivateKey);
                    parser.Key = Console.ReadLine();
                }

                if (string.IsNullOrEmpty (parser.Password))
                {
                    Console.WriteLine(Strings.MsgDecryptKeyPassword);
                    parser.Password = MaskPassword();
                }
            }
            else
            {
                if (string.IsNullOrEmpty(parser.Password))
                {
                    Console.WriteLine(Strings.MsgEnterPasswordDecryption);
                    parser.Password = MaskPassword();
                }
            }


            // Now check if the destination exists . If it does, ask for confirmation but only if -y is not given in the command line // first, check if the destination exists . If it does, ask for confirmation but only if -y is not given in the command line

            if (File.Exists(destination))
            {
                if (!parser.Yes)
                {
                    answer = AnswerQuestion(string.Format(CultureInfo.CurrentCulture, Strings.MsgReplaceFile, destination),
                        partOfMassOp, partOfMassOp);

                    if ((answer == ConsoleAnswer.No) || (answer == ConsoleAnswer.Cancel))
                    {
                        ShowMessageLaconic(Strings.MsgAborted);
                        return Constants.ExitOperationAbortedByTheUser;
                    }

                    if (answer == ConsoleAnswer.All)
                        parser.Yes = true;
                }
            }

            ShowMessageLaconic(string.Format(CultureInfo.CurrentCulture, Strings.MsgDecryptingFile, source));

            try
            {
                Crypto.DecryptFile(source, destination, parser.Key, parser.Password, null);

                return Constants.ExitOk;
            }
            catch (CryptographicException e)
            {
                ShowError(string.Format(CultureInfo.CurrentCulture, Strings.ErrCryptoError, e.Message));
                return Constants.ExitCryptoError;
            }
            catch (NotSupportedException e)
            {
                ShowError(string.Format(CultureInfo.CurrentCulture, Strings.ErrNotSupported, e.Message));
                return Constants.ExitNotSupported;
            }

            catch (IOException e)
            {
                ShowError(string.Format(CultureInfo.CurrentCulture, Strings.ErrIOError, e.Message));
                return Constants.ExitIOError;
            }
            catch (SecurityException e)
            {
                ShowError(string.Format(CultureInfo.CurrentCulture, Strings.ErrSecurityException, e.Message));
                return Constants.ExitSecurityError;
            }
            catch (UnauthorizedAccessException e)
            {
                ShowError(string.Format(CultureInfo.CurrentCulture, Strings.ErrSecurityException, e.Message));
                return Constants.ExitSecurityError;
            }
            catch (Exception e)
            {
                ShowError(string.Format(CultureInfo.CurrentCulture, Strings.ErrUnexpectedError, e.Message));
                return Constants.ExitUnexpectedError;
            }
        }

        /// <summary>
        /// This is called by the single file operation but also by recursive methods
        /// </summary>
        /// <param name="source">The source</param>
        /// <param name="destination">The destination</param>
        /// <param name="answer">Some answer in case of any questions</param>
        /// <param name="partOfMassOp">Is this operation called as a part of a mass operation?</param>
        /// <returns>The result of the operation</returns>
        private static int EncryptSingleFile([NotNull] string source, [NotNull] string destination, bool partOfMassOp, out ConsoleAnswer answer)
        {
            answer = ConsoleAnswer.Yes;

            if (parser == null)
                return Constants.ExitNoParser;

            // first, check if the destination exists . If it does, ask for confirmation but only if -y is not given in the command line

            if (File.Exists(destination))
            {
                if (!parser.Yes)
                {
                    answer = AnswerQuestion(string.Format(CultureInfo.CurrentCulture, Strings.MsgReplaceFile, destination),
                        partOfMassOp, partOfMassOp);

                    if ((answer == ConsoleAnswer.No) || (answer == ConsoleAnswer.Cancel))
                    {
                        ShowMessageLaconic(Strings.MsgAborted);
                        return Constants.ExitOperationAbortedByTheUser;
                    }

                    if (answer == ConsoleAnswer.All)
                        parser.Yes = true;
                }
            }

            ShowMessageLaconic(string.Format(CultureInfo.CurrentCulture, Strings.MsgEncryptingFile, source));

            try
            {
                Crypto.EncryptFile(parser.Method ?? EncryptionMethod.AES256, source, destination, parser.Key, parser.Password, null);

                if (parser.DeleteAfterEncryption)
                {
                    try
                    {
                        File.Delete(source);
                        ShowMessageLaconic(string.Format(CultureInfo.CurrentCulture, Strings.MsgFileDeleted, source));
                    }
                    catch
                    {
                        ShowMessageLaconic(string.Format(CultureInfo.CurrentCulture, Strings.MsgDeletionError, source));
                        throw;
                    }
                }

                return Constants.ExitOk;
            }
            catch (CryptographicException e)
            {
                ShowError(string.Format(CultureInfo.CurrentCulture, Strings.ErrCryptoError, e.Message));
                return Constants.ExitCryptoError;
            }
            catch (NotSupportedException e)
            {
                ShowError(string.Format(CultureInfo.CurrentCulture, Strings.ErrNotSupported, e.Message));
                return Constants.ExitNotSupported;
            }

            catch (IOException e)
            {
                ShowError(string.Format(CultureInfo.CurrentCulture, Strings.ErrIOError, e.Message));
                return Constants.ExitIOError;
            }
            catch (SecurityException e)
            {
                ShowError(string.Format(CultureInfo.CurrentCulture, Strings.ErrSecurityException, e.Message));
                return Constants.ExitSecurityError;
            }
            catch (UnauthorizedAccessException e)
            {
                ShowError(string.Format(CultureInfo.CurrentCulture, Strings.ErrSecurityException, e.Message));
                return Constants.ExitSecurityError;
            }
            catch (Exception e)
            {
                ShowError(string.Format(CultureInfo.CurrentCulture, Strings.ErrUnexpectedError, e.Message));
                return Constants.ExitUnexpectedError;
            }
        }

        private static int DecryptDirectory()
        {
            if (parser == null)
                return Constants.ExitNoParser;

            parser.Source = Path.Combine(parser.Source ?? string.Empty, Constants.AllFiles);

            return DecryptMask();
        }

        private static int EncryptDirectory()
        {
            if (parser == null)
                return Constants.ExitNoParser;

            parser.Source = Path.Combine(parser.Source ?? string.Empty, Constants.AllFiles);

            return EncryptMask();
        }

        private static int DecryptMask()
        {
            if (parser == null)
                return Constants.ExitNoParser;

            long files = 0, errors = 0, directories = 0;

            string? dir = Path.GetDirectoryName(parser.Source);

            if (string.IsNullOrEmpty(dir))
                dir = Environment.CurrentDirectory;

            string? mask = Path.GetFileName(parser.Source);

            if (string.IsNullOrEmpty(mask))
                mask = Constants.AllFiles;

            ConsoleAnswer answer = ConsoleAnswer.Yes;

            int result = DecryptDirectoryRecursively(dir, mask, parser.Destination ?? string.Empty, ref files, ref directories, ref errors, ref answer);

            ShowSpecialMessage(string.Format(CultureInfo.CurrentCulture,
                Strings.MsgMassDecryption, files, directories, errors));

            return result;
        }

        private static int EncryptMask()
        {
            if (parser == null)
                return Constants.ExitNoParser;

            long files = 0, errors = 0, directories = 0;

            string? dir = Path.GetDirectoryName(parser.Source);

            if (string.IsNullOrEmpty(dir))
                dir = Environment.CurrentDirectory;

            string? mask = Path.GetFileName(parser.Source);

            if (string.IsNullOrEmpty(mask))
                mask = Constants.AllFiles;

            ConsoleAnswer answer = ConsoleAnswer.Yes;

            int result = EncryptDirectoryRecursively(dir, mask, parser.Destination ?? string.Empty, ref files, ref directories, ref errors, ref answer);

            ShowSpecialMessage(string.Format(CultureInfo.CurrentCulture,
                Strings.MsgMassEncryption, files, directories, errors));

            return result;
        }

        private static int DecryptDirectoryRecursively(string directory, string mask, string destination, ref long files, ref long folders, ref long errors, ref ConsoleAnswer answer)
        {
            if (answer == ConsoleAnswer.Cancel)
            {
                return Constants.ExitOperationAbortedByTheUser;
            }

            if (parser == null)
                return Constants.ExitNoParser;

            if (!Directory.Exists(destination))
            {
                try
                {
                    ShowMessageLaconic(string.Format(CultureInfo.CurrentCulture, Strings.MsgCreatingDirectory, destination));
                    Directory.CreateDirectory(destination);
                    folders++;

                }
                catch (IOException e)
                {
                    errors++;
                    ShowError(string.Format(CultureInfo.CurrentCulture, Strings.ErrIOError, e.Message));
                    return Constants.ExitIOError;
                }
                catch (SecurityException e)
                {
                    errors++;
                    ShowError(string.Format(CultureInfo.CurrentCulture, Strings.ErrSecurityException, e.Message));
                    return Constants.ExitSecurityError;
                }
                catch (UnauthorizedAccessException e)
                {
                    errors++;
                    ShowError(string.Format(CultureInfo.CurrentCulture, Strings.ErrSecurityException, e.Message));
                    return Constants.ExitSecurityError;
                }
                catch (Exception e)
                {
                    errors++;
                    ShowError(string.Format(CultureInfo.CurrentCulture, Strings.ErrUnexpectedError, e.Message));
                    return Constants.ExitUnexpectedError;
                }
            }

            DirectoryInfo[] ods;
            FileInfo[] ofs;

            try
            {
                DirectoryInfo info = new(directory);
                ods = info.GetDirectories(Constants.AllFiles, SearchOption.TopDirectoryOnly);
                ofs = info.GetFiles(mask, SearchOption.TopDirectoryOnly);
            }
            catch (SecurityException e)
            {
                errors++;
                ShowError(string.Format(CultureInfo.CurrentCulture, Strings.ErrSecurityException, e.Message));
                return Constants.ExitSecurityError;
            }
            catch (IOException e)
            {
                errors++;
                ShowError(string.Format(CultureInfo.CurrentCulture, Strings.ErrIOError, e.Message));
                return Constants.ExitIOError;
            }
            catch (Exception e)
            {
                errors++;
                ShowError(string.Format(CultureInfo.CurrentCulture, Strings.ErrUnexpectedError, e.Message));
                return Constants.ExitUnexpectedError;
            }

            if (parser.Recursive)
                foreach (var d in ods)
                {
                    _ = DecryptDirectoryRecursively(Path.Combine(directory, d.Name), mask, Path.Combine(destination, d.Name), ref files, ref folders, ref errors, ref answer);

                    if (answer == ConsoleAnswer.Cancel)
                        return Constants.ExitOperationAbortedByTheUser;
                }

            foreach (var f in ofs)
            {
                if (OperatingSystem.IsWindows())
                {
                    if (f.Attributes.HasFlag(FileAttributes.Hidden) && !parser.Hidden)
                        continue;
                }
                else
                {
                    if ((f.Name.IndexOf(Constants.CharHidden, StringComparison.Ordinal) == 0) && !parser.Hidden)
                        continue;
                }

                string d = f.Name;

                if (Constants.ExtEncrypted.Equals(Path.GetExtension(d), StringComparison.Ordinal))
                    d = d[..^Constants.ExtEncrypted.Length];

                var result = DecryptSingleFile(Path.Combine(directory, f.Name),
                    Path.Combine(destination, d), true, out answer);

                if (answer == ConsoleAnswer.Cancel)
                    return Constants.ExitOperationAbortedByTheUser;

                if (result == Constants.ExitOk)
                    files++;
                else
                    errors++;
            }

            return errors == 0 ? Constants.ExitOk : Constants.ExitSeveralErrors;
        }

        private static int EncryptDirectoryRecursively(string directory, string mask, string destination, ref long files, ref long folders, ref long errors, ref ConsoleAnswer answer)
        {
            if (answer == ConsoleAnswer.Cancel)
            {
                return Constants.ExitOperationAbortedByTheUser;
            }

            if (parser == null)
                return Constants.ExitNoParser;

            if (!Directory.Exists(destination))
            {
                try
                {
                    ShowMessageLaconic(string.Format(CultureInfo.CurrentCulture, Strings.MsgCreatingDirectory, destination));
                    Directory.CreateDirectory(destination);
                    folders++;

                }
                catch (IOException e)
                {
                    errors++;
                    ShowError(string.Format(CultureInfo.CurrentCulture, Strings.ErrIOError, e.Message));
                    return Constants.ExitIOError;
                }
                catch (SecurityException e)
                {
                    errors++;
                    ShowError(string.Format(CultureInfo.CurrentCulture, Strings.ErrSecurityException, e.Message));
                    return Constants.ExitSecurityError;
                }
                catch (UnauthorizedAccessException e)
                {
                    errors++;
                    ShowError(string.Format(CultureInfo.CurrentCulture, Strings.ErrSecurityException, e.Message));
                    return Constants.ExitSecurityError;
                }
                catch (Exception e)
                {
                    errors++;
                    ShowError(string.Format(CultureInfo.CurrentCulture, Strings.ErrUnexpectedError, e.Message));
                    return Constants.ExitUnexpectedError;
                }
            }

            DirectoryInfo[] ods;
            FileInfo[] ofs;

            try
            {
                DirectoryInfo info = new(directory);
                ods = info.GetDirectories(Constants.AllFiles, SearchOption.TopDirectoryOnly);
                ofs = info.GetFiles(mask, SearchOption.TopDirectoryOnly);
            }
            catch (SecurityException e)
            {
                errors++;
                ShowError(string.Format(CultureInfo.CurrentCulture, Strings.ErrSecurityException, e.Message));
                return Constants.ExitSecurityError;
            }
            catch (IOException e)
            {
                errors++;
                ShowError(string.Format(CultureInfo.CurrentCulture, Strings.ErrIOError, e.Message));
                return Constants.ExitIOError;
            }
            catch (Exception e)
            {
                errors++;
                ShowError(string.Format(CultureInfo.CurrentCulture, Strings.ErrUnexpectedError, e.Message));
                return Constants.ExitUnexpectedError;
            }

            if (parser.Recursive)
                foreach (var d in ods)
                {
                    _ = EncryptDirectoryRecursively(Path.Combine(directory, d.Name), mask, Path.Combine(destination, d.Name), ref files, ref folders, ref errors, ref answer);

                    if (answer == ConsoleAnswer.Cancel)
                        return Constants.ExitOperationAbortedByTheUser;
                }

            foreach (var f in ofs)
            {
                if (OperatingSystem.IsWindows())
                {
                    if (f.Attributes.HasFlag(FileAttributes.Hidden) && !parser.Hidden)
                        continue;
                }
                else
                {
                    if ((f.Name.IndexOf(Constants.CharHidden, StringComparison.Ordinal) == 0) && !parser.Hidden)
                        continue;
                }

                var result = EncryptSingleFile(Path.Combine(directory, f.Name),
                    Path.Combine(destination, f.Name + Constants.ExtEncrypted), true, out answer);

                if (answer == ConsoleAnswer.Cancel)
                    return Constants.ExitOperationAbortedByTheUser;

                if (result == Constants.ExitOk)
                    files++;
                else
                    errors++;

            }

            return errors == 0 ? Constants.ExitOk : Constants.ExitSeveralErrors;
        }

        /// <summary>
        /// Gets the type of a source or a destination
        /// </summary>
        /// <param name="sd">The source or destination</param>
        /// <returns>The type</returns>
        private static SDType GetSDType(string sd)
        {
            if (File.Exists(sd))
                return SDType.File;

            if (Directory.Exists(sd))
                return SDType.Directory;

            if (sd.Contains(Constants.AnyChars, StringComparison.Ordinal) || sd.Contains(Constants.OneCharChar, StringComparison.Ordinal))
            {
                return SDType.Mask;
            }


            return SDType.Unknown;
        }


        /// <summary>
        /// Decrypt a file, directory or mask
        /// </summary>
        /// <returns></returns>
        private static int Decrypt()
        {
            if (parser == null)
            {
                Console.WriteLine(Strings.ErrParserNotFound);
                return Constants.ExitNoParser;
            }

            if (string.IsNullOrEmpty(parser.Source))
            {
                Console.WriteLine(Strings.MsgEnterSourceD);
                parser.Source = Console.ReadLine();
            }

            if (string.IsNullOrEmpty(parser.Source))
            {
                Console.WriteLine(Strings.ErrNoSourceD);
                return Constants.ExitNoSource;
            }

            if (string.IsNullOrEmpty(parser.Destination))
            {
                Console.WriteLine(Strings.MsgEnterDestination);
                parser.Destination = Console.ReadLine();
            }


            if (string.IsNullOrEmpty(parser.Destination))
            {
                Console.WriteLine(Strings.ErrNoDestination);
                return Constants.ExitNoDestination;
            }

            if (string.IsNullOrEmpty(parser.Key))
            {
                if (!string.IsNullOrEmpty(parser.KeyForDecryption))
                    parser.Key = parser.KeyForDecryption;
            }

            var kind = GetSDType(parser.Source);

            switch (kind)
            {
                case SDType.Unknown:
                    {
                        Console.WriteLine(string.Format(CultureInfo.CurrentCulture, Strings.ErrUnknownSource, parser.Source));
                        return Constants.ExitUnknownSource;
                    }
                case SDType.File:
                    {
                        return DecryptFile();
                    }
                case SDType.Directory:
                    {
                        return DecryptDirectory();
                    }
                case SDType.Mask:
                    {
                        return DecryptMask();
                    }
                default:
                    {
                        Console.WriteLine(string.Format(CultureInfo.CurrentCulture, Strings.ErrUnknownSource, parser.Source));
                        return Constants.ExitUnknownSource;
                    }
            }
        }

        /// <summary>
        /// Parses and analyzes all command line arguments
        /// </summary>
        /// <param name="args">The command line arguments</param>
        private static int AnalyzeArguments(string[] args)
        {
            if (parser == null)
            {
                ShowError(Strings.ErrNoParser);
                return Constants.ExitNoArguments;
            }

            switch (parser.Command)
            {
                case Verb.NoVerb:
                    {
                        ShowError(Strings.ErrNoVerb);
                        return Constants.ExitNoArguments;
                    }
                case Verb.Help:
                    {
                        ShowHelp();
                        break;
                    }
                case Verb.Version: //same as about
                case Verb.About:
                    {
                        ShowAbout();
                        break;
                    }
                case Verb.CreateKeys:
                    {
                        return CreateKeyPair();
                    }
                case Verb.Encrypt:
                    {
                        return Encrypt();
                    }
                case Verb.Decrypt:
                    {
                        return Decrypt();
                    }
                case Verb.EncryptPassword:
                    {
                        return EncryptPassword();
                    }
                case Verb.Config:
                    {
                        return CreateConfigFile();
                    }
                default:
                    {
                        ShowError(Strings.ErrUnknownVerb);
                        return Constants.ExitNoArguments;
                    }
            }

#if DEBUG
            Console.ReadLine();
#endif

            return Constants.ExitOk;
        }
    }
}
