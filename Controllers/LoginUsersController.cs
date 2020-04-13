using System;
using System.Collections.Generic;
using System.Data;
using System.Data.Entity;
using System.Linq;
using System.Net;
using System.Web;
using System.Web.Mvc;
using COVID19_Part2_WebApi;
using System.Security.Cryptography;
using System.Text;

namespace COVID19_Part2_WebApi.Controllers
{
    public class LoginUsersController : Controller
    {
        private Covid_19_PackingEntities db = new Covid_19_PackingEntities();

        private static RSAParameters publicKey;
        private static RSAParameters privateKey;

        public LoginUsersController()
        {
            GenerateKeys();
        }

        private void GenerateKeys()
        {
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.PersistKeyInCsp = false;
                publicKey = rsa.ExportParameters(false);
                privateKey = rsa.ExportParameters(true);
            }
        }

        // POST: LoginUsers/GetPublicKey?password={enterPassword}
        public ActionResult GetPublicKey(string password)
        {
            if (password == "password")
            {
                return Json(publicKey);
            }
            return Json("Password incorrect! Application will now close!");
        }

        public ActionResult Login(byte[] username, byte[] password)
        {
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.PersistKeyInCsp = false;
                rsa.ImportParameters(privateKey);
                var decryptedUsername = Encoding.UTF8.GetString(rsa.Decrypt(username, true));
                var decrytedPassword = rsa.Decrypt(password, true);
                var getUser = (from x in db.LoginUsers
                               where x.LoginID == decryptedUsername && x.LoginPassword == decrytedPassword
                               select x).FirstOrDefault();
                if (getUser != null)
                {
                    return Json(getUser);
                }
                return Json("User not found or credentials are incorrect!");
            }
        }


        // POST: LoginUsers/Create
        [HttpPost]
        public ActionResult Create([Bind(Include = "ID,LoginID,LoginPassword,FullName,LastLogin,LoginFail,AccountIsLocked")] LoginUser loginUser)
        {
            if (ModelState.IsValid)
            {
                db.LoginUsers.Add(loginUser);
                db.SaveChanges();
                return RedirectToAction("Index");
            }

            return View(loginUser);
        }


        // POST: LoginUsers/Edit/5
        [HttpPost]
        public ActionResult Edit([Bind(Include = "ID,LoginID,LoginPassword,FullName,LastLogin,LoginFail,AccountIsLocked")] LoginUser loginUser)
        {
            if (ModelState.IsValid)
            {
                db.Entry(loginUser).State = EntityState.Modified;
                db.SaveChanges();
                return RedirectToAction("Index");
            }
            return View(loginUser);
        }

        // POST: LoginUsers/Delete/5
        [HttpPost, ActionName("Delete")]
        public ActionResult DeleteConfirmed(int id)
        {
            LoginUser loginUser = db.LoginUsers.Find(id);
            db.LoginUsers.Remove(loginUser);
            db.SaveChanges();
            return RedirectToAction("Index");
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                db.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}
