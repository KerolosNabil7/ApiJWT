using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;

namespace TestApiJWT.Models
{
    public class ApplicationUser : IdentityUser //(Add Identity to the Project and customize the Identity UserClass to have those new 2 fields)
    {
        [Required, MaxLength(50)]
        public string FirstName { get; set; }

        [Required, MaxLength(50)]
        public string LastName { get; set; }
    }
}
