<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="MyPage.aspx.cs" Inherits="Kombit.Samples.CH.WebsiteDemo.WebForm1" MasterPageFile="~/sp.Master"%>
<%@ Import Namespace="dk.nita.saml20.identity" %>
<%@ Import Namespace="dk.nita.saml20.Schema.Core" %>
<asp:Content ID="Content2" runat="server" ContentPlaceHolderID="ContentPlaceHolder1">
    <% ValidateKombitAttributeProfile(Saml20Identity.Current);
       %>
    <% if (System.Configuration.ConfigurationManager.AppSettings["OfferAssuranceLevel"] != "true" &&
            Saml20Identity.Current["https://data.gov.dk/concept/core/nsis/loa"][0].AttributeValue[0] == "Low")
       {
           throw new Exception("Saml assertion does not have required assurance level.");
       } %>
    <% if (Saml20Identity.IsInitialized())
       { %>
    <div class="div-claim">
        <div class="div-metadata-mypage-title" >
            <span class="title"><b>My page:</b></span>
        </div>
        <b>WELCOME, <%= Saml20Identity.Current.Name %></b>
        <table>
            <thead>
                <tr>
                    <th style="width:50%">
                        <h4><b>Attribute name</b></h4>
                    </th>
                    <th  style="width:50%">
                        <h4><b>Attribute value</b></h4>
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

        <div><asp:Button CssClass="btn btn-info" Id="btnLogoff" runat="server" Enabled="true" Text="Logoff" OnClick="Btn_Logoff_Click" /></div>
        <hr style="border-top:dotted; border-width:1px;" />
        <div>Relogin with IdP: 
        <asp:Button Id="Btn_Relogin" CssClass="btn btn-info" runat="server" Enabled="true" Text="ForceAuthn" OnClick="Btn_Relogin_Click" />
        <asp:Button Id="Btn_Passive" CssClass="btn btn-info" runat="server" Enabled="true" Text="Passive login" OnClick="Btn_Passive_Click" />
        <asp:Button Id="Btn_ReloginNoForceAuthn" CssClass="btn btn-info" runat="server" Enabled="true" Text="No ForceAuthn" OnClick="Btn_ReloginNoForceAuthn_Click" />
        <% if (System.Configuration.ConfigurationManager.AppSettings["OfferAssuranceLevel"] == "true")
        { %>
            <asp:Button Id="Btn_ReloginNoForceAuthn_NSISAssuranceLevelLow" CssClass="btn btn-info" runat="server" Enabled="true" Text="No ForceAuthn - NSIS Assurance Level Low" OnClick="Btn_ReloginNoForceAuthnNSISAssuranceLevelLow_Click" />
            <asp:Button Id="Btn_ReloginNoForceAuthn_NSISAssuranceLevelSubstantial" CssClass="btn btn-info" runat="server" Enabled="true" Text="No ForceAuthn - NSIS Assurance Level Substantial" OnClick="Btn_ReloginNoForceAuthnNSISAssuranceLevelSubstantial_Click" />
            <asp:Button Id="Btn_ReloginNoForceAuthn_NSISAssuranceLevelHigh" CssClass="btn btn-info" runat="server" Enabled="true" Text="No ForceAuthn - NSIS Assurance Level High" OnClick="Btn_ReloginNoForceAuthnNSISAssuranceLevelHigh_Click" />            
        
        <% } %>
            <hr style="border-top:dotted;  border-width:1px;" />
        </div>
    </div>
    <% } %>

    
</asp:Content>
