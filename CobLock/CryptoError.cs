
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

namespace Cobian.Locker.Cryptography
{
    /// <summary>
    /// Errors when the decryption result is null
    /// </summary>
    internal enum CryptoError
    {
        /// <summary>
        /// No error
        /// </summary>
        None,
        /// <summary>
        /// The password is empty
        /// </summary>
        EmptyPassword,
        /// <summary>
        /// This is not a string that was encrypted with this class
        /// </summary>
        UnknownEncryptionMethod,
        /// <summary>
        /// The header of the string is malformed
        /// </summary>
        BadHeader,
        /// <summary>
        /// The password was bad or the string is corrupted
        /// </summary>
        BadPasswordOrCorruptedString,
        /// <summary>
        /// The input string is null
        /// </summary>
        BadInput,
        /// <summary>
        /// Some unknown error
        /// </summary>
        UnknownError

    }
}
