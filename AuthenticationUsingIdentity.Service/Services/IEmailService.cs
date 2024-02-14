using AuthenticationUsingIdentity.Service.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AuthenticationUsingIdentity.Service.Services
{
    public interface IEmailService
    {
        void sendEmail(Message message);
    }
}
