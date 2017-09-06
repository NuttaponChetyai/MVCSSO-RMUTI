using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using OneLogin;
using System.Xml;
using MVCSSO.Models;
namespace MVCSSO.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            return RedirectToAction("Sso");
        }
        // ล็อกอิน
        public ActionResult Sso()
        {
            AppSettings appSettings = new AppSettings();
            Auth auth = new Auth(appSettings);
            string redirect = "";
            if (Request.QueryString["redirect"] != null)
            {
                redirect = Request.QueryString["redirect"];
            }
            else if (Request.UrlReferrer != null)
            {
                redirect = Request.UrlReferrer.ToString();
            }
            if (redirect != "")
            {
                auth.Login(redirect);
            }
            else
            {
                auth.Login();
            }
            return new EmptyResult();
        }
        // ล็อกอินผ่าน
        public ActionResult Acs(){
            AppSettings appSettings = new AppSettings();
            Auth auth = new Auth(appSettings);
            auth.ProcessResponse();
            var res = string.Empty;
            var name = string.Empty;
            var ssoValue = string.Empty;
            var modelSso = new ModelSSO();
            if (auth.Response.IsValid())
            {

                HttpContext.Session["ssoNameID"] = auth.Response.GetNameID();

                HttpContext.Session["ssoSessionIndex"] = auth.Response.GetSessionIndex();

                HttpContext.Session["ssoUserData"] = auth.Response.GetAttributes();

                if (Request.Form["RelayState"] != null)
                {
                    res = Request.Form["RelayState"].ToString();
                }
                if (HttpContext.Session["ssoUserData"] != null)
                {
                    XmlDocument userXmlDoc = new XmlDocument();
                    userXmlDoc.PreserveWhitespace = true;
                    userXmlDoc.XmlResolver = null;
                    userXmlDoc.LoadXml((string)HttpContext.Session["ssoUserData"]);

                    foreach (XmlNode node in userXmlDoc.FirstChild.ChildNodes)
                    {
                        name = node.Attributes["Name"].Value;
                        ssoValue = node.FirstChild.InnerText;
                        switch (name)
                        {
                            case "uid":
                                modelSso.UserName = ssoValue;
                                break;
                            case "gidNumber":
                                modelSso.GridNumber = ssoValue;
                                break;
                            case "firstNameThai":
                                modelSso.FirstName = ssoValue;
                                break;
                            case "lastNameThai":
                                modelSso.LastName = ssoValue;
                                break;
                            case "personalId":
                                modelSso.PersonalId = ssoValue;
                                break;
                            case "program":
                                modelSso.Program = ssoValue;
                                break;
                            case "mail":
                                modelSso.Email = ssoValue;
                                break;
                            default:
                                break;
                        }
                    }
                    return RedirectToAction("Index", "Manage", modelSso);

                }
                else
                {
                    // ไม่มีข้อมูลผู้ใช้งาน
                    return new EmptyResult();
                }
            }
            else {
                //ไม่มีการล็อกอิน
                return new EmptyResult();
            }
            
        }
        // ล็อกเอา
        public ActionResult Slo() {
            AppSettings appSettings = new AppSettings();
            Auth auth = new Auth(appSettings);
            HttpContext.Session["ssoUserData"] = null;
            string nameId = (string)HttpContext.Session["ssoNameID"];
            string sessionIndex = (string)HttpContext.Session["ssoSessionIndex"];

            string redirect = "";
            if (Request.QueryString["redirect"] != null)
            {
                redirect = Request.QueryString["redirect"];
            }
            else if (Request.UrlReferrer != null)
            {
                redirect = Request.UrlReferrer.ToString();
            }

            if (redirect != "")
            {
                auth.Logout(redirect, nameId, sessionIndex);
            }
            else
            {
                auth.Logout("", nameId, sessionIndex);
            }
            Response.End();
            return new EmptyResult();
        }
        // ล็อกเอาท์เสร็จแล้ว
        public ActionResult Sls() {
            AppSettings appSettings = new AppSettings();
            Auth auth = new Auth(appSettings);
            if (Request.Form["SAMLResponse"] != null)
            {
                auth.ProcessResponse();

                if (auth.Response.IsValid())
                {
                    HttpContext.Session["ssoNameID"] = null;
                    HttpContext.Session["ssoSessionIndex"] = null;
                    HttpContext.Session.Clear();
                    HttpContext.Session.RemoveAll();
                    HttpContext.Session.Abandon();
                    Session.RemoveAll();
                    Session.Clear();
                    Session.Abandon();
                    if (Request.Form["RelayState"] != null)
                    {
                        return Redirect(Request.Form["RelayState"]);
                    }
                    else
                    {
                        return RedirectToAction("Index");
                    }
                }
                else
                {
                    HttpContext.Session.Clear();
                    HttpContext.Session.RemoveAll();
                    HttpContext.Session.Abandon();
                    Session.RemoveAll();
                    Session.Clear();
                    Session.Abandon();
                    return RedirectToAction("Index");
                }
            }
            else
            {
                HttpContext.Session.Clear();
                HttpContext.Session.RemoveAll();
                HttpContext.Session.Abandon();
                Session.RemoveAll();
                Session.Clear();
                Session.Abandon();
                return RedirectToAction("Index");
            }
        }
    }
}