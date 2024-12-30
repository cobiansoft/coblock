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
    /// The encryption method to use
    /// </summary>
    internal enum EncryptionMethod
    {
        /// <summary>
        /// Use the AES method, 128 bits key, symmetric
        /// </summary>
        AES128 = 0,
        /// <summary>
        /// AES 192 bits key, symmetric
        /// </summary>
        AES192 = 1,
        /// <summary>
        /// AES 256 bits, symmetric
        /// </summary>
        AES256 = 2,
        /// <summary>
        /// Use the RSA method, asymmetric
        /// </summary>
        RSA = 3,

        /// <summary>
        /// Unknown method
        /// </summary>
        UnknownMethod = 1924
    }
}
