
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
    /// The size of the key pair to create
    /// </summary>
    internal enum AsymmetricKeySize
    {
        /// <summary>
        /// Unsupported
        /// </summary>
        UnsupportedSize = 0,

        /// <summary>
        /// 1024 key size
        /// </summary>
        Size1024 = 1024,

        /// <summary>
        /// 2048 key size
        /// </summary>
        Size2048 = 2048,

        /// <summary>
        /// 3072 key size
        /// </summary>
        Size3072 = 3072,

        /// <summary>
        /// 4096 key size
        /// </summary>
        Size4096 = 4096,

        /// <summary>
        /// 7680 key size
        /// </summary>
        Size7680 = 7680,

        /// <summary>
        /// 8192 key size
        /// </summary>
        Size8192 = 8192


    }
}
