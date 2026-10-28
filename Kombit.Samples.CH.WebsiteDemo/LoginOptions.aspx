<%@ Page Language="C#" AutoEventWireup="true" EnableSessionState="true" CodeBehind="LoginOptions.aspx.cs" Inherits="Kombit.Samples.CH.WebsiteDemo.LoginOptions" MasterPageFile="~/sp.Master" Title="Sign in" %>
<%@ MasterType VirtualPath="~/sp.Master" %>

<asp:Content ID="Content2" ContentPlaceHolderID="ContentPlaceHolder1" runat="server">
    <div class="login-page">
        <div class="login-intro">
            <h1>Sign in</h1>
            <p>Choose how you want to sign in to the demo service provider.</p>
        </div>

        <div class="login-options">
            <section class="login-card" aria-labelledby="idp-title">
                <h2 id="idp-title" class="login-card-title">Choose Identity Provider</h2>
                <p class="login-card-text">Continue with the identity provider that manages your account.</p>
                <ul class="idp-list">
                    <% foreach (var idp in IdentityProviders)
                       { %>
                    <li>
                        <% if (idp.Available)
                           { %>
                        <a class="idp-option" href="<%: idp.LoginUrl %>">
                            <span class="idp-text">
                                <span class="idp-name"><%: idp.Name %></span>
                                <span class="idp-address"><%: idp.Address %></span>
                            </span>
                            <span class="idp-arrow" aria-hidden="true">&rsaquo;</span>
                        </a>
                        <% }
                           else
                           { %>
                        <span class="idp-option is-unavailable" aria-disabled="true">
                            <span class="idp-text">
                                <span class="idp-name"><%: idp.Name %></span>
                                <span class="idp-address"><%: idp.Address %></span>
                            </span>
                            <span class="idp-status">Metadata not found</span>
                        </span>
                        <% } %>
                    </li>
                    <% } %>
                </ul>
            </section>

            <% if (EmergencyAvailable)
               { %>
            <section id="emergency-login-option" class="login-card login-card-alt" aria-labelledby="alt-title" hidden="hidden"
                data-api="<%: ResolveUrl("~/EmergencyApi.ashx") %>" data-csrf="<%: EmergencyCsrf %>" data-authenticator="<%: Kombit.Samples.CH.WebsiteDemo.EmergencyFeature.EmergencyWeb.Authenticator %>">
                <h2 id="alt-title" class="login-card-title">Other login options</h2>
                <p class="login-card-text">This browser has an emergency key. Use it only when normal sign-in through your identity provider is unavailable.</p>
                <div id="emergency-login-actions" class="login-alt-actions"></div>
                <p id="emergency-login-status" class="login-alt-status" role="status" aria-live="polite" hidden="hidden"></p>
                <p class="login-card-note">You will be asked to confirm with your security key or passkey.</p>
            </section>
            <% } %>
        </div>
    </div>
    <% if (EmergencyAvailable)
       { %>
    <script type="text/javascript" src="<%: Master.AssetUrl("~/EmergencyAssets/login-options.js") %>"></script>
    <% } %>
</asp:Content>
