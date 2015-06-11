<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="MyPage.aspx.cs" Inherits="Kombit.Samples.CH.WebsiteDemo.WebForm1" MasterPageFile="~/sp.Master"%>
<%@ Import Namespace="dk.nita.saml20.identity" %>
<%@ Import Namespace="dk.nita.saml20.Schema.Core" %>
<asp:Content runat="server" ID="Content1" ContentPlaceHolderID="head">
    <style type="text/css">
        table {
            background-color: white;
            border-collapse: collapse;
            border-color: black;
            border-spacing: 2px;
            border-style: solid;
            border-width: 1px;
        }

        table th {
            border-color: gray;
            border-style: dotted;
            border-width: 1px;
            padding: 3px;
        }

        table td {
            background-color: white;
            border-color: gray;
            border-style: dotted;
            border-width: 1px;
            padding: 3px;
        }
    </style>
</asp:Content>
<asp:Content ID="Content2" runat="server" ContentPlaceHolderID="ContentPlaceHolder1">
    <% if (!ValidateKombitAttributeProfile(Saml20Identity.Current))
       {
           throw new Exception("Saml assertion does not meet Kombit profile. It must have AssuranceLevel, SpecVer, KombitSpecVer, Service and Previlege");
       } %>
    <% if (int.Parse(Saml20Identity.Current["dk:gov:saml:attribute:AssuranceLevel"][0].AttributeValue[0]) < 3)
       {
           throw new Exception("Saml assertion does not have required assurance level.");
       } %>
    <% if (Saml20Identity.IsInitialized())
       { %>
    <div>
        Welcome, <%= Saml20Identity.Current.Name + (Saml20Identity.Current.PersistentPseudonym != null ? " (Pseudonym is " + Saml20Identity.Current.PersistentPseudonym + ")" : String.Empty) %><br />
        <table style="border: solid 1px;">
            <thead>
                <tr>
                    <th>
                        Attribute name
                    </th>
                    <th>
                        Attribute value
                    </th>
                </tr>
            </thead>
            <% foreach (SamlAttribute att in Saml20Identity.Current)
               { %>
            <tr>
                <td>
                    <%= att.Name %>
                </td>
                <td>
                    <%= att.AttributeValue.Length > 0 ? RenderAttributeValue(att.Name, att.AttributeValue[0]) : string.Empty %>
                </td>
            </tr>
            <% } %>
        </table>
    </div>
    <% } %>

    <div><asp:Button Id="btnLogoff" runat="server" Enabled="true" Text="Logoff" OnClick="Btn_Logoff_Click" /></div>
    <br />
    <div>Relogin with IdP: 
    <asp:Button Id="Btn_Relogin" runat="server" Enabled="true" Text="ForceAuthn" OnClick="Btn_Relogin_Click" />
    <asp:Button Id="Btn_Passive" runat="server" Enabled="true" Text="Passive login" OnClick="Btn_Passive_Click" />
    <asp:Button Id="Btn_ReloginNoForceAuthn" runat="server" Enabled="true" Text="No ForceAuthn" OnClick="Btn_ReloginNoForceAuthn_Click" />
    
    </div>
</asp:Content>
