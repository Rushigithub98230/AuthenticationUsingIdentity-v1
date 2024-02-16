﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AuthenticationUsingIdentity.Service.Models.User
{
    public class LoginResponse
    {
        public TokenType AccessToken { get; set; }
        public TokenType RefreshToken { get; set; }
    }
}
