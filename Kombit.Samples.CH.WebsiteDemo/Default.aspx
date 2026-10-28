<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="Default.aspx.cs" MasterPageFile="~/sp.Master" Inherits="Kombit.Samples.CH.WebsiteDemo._Default" Title="Demo Service Provider" %>

<%@ Import Namespace="dk.nita.saml20.config" %>
<asp:Content ID="Content2" ContentPlaceHolderID="ContentPlaceHolder1" runat="server">
    <div class="row">
        <div class="col-md-12">
            <div class="div-row-btn-mypage">
                <% if (HasNormalSession)
                   { %>
                <a href="MyPage.aspx" class="btn btn-info">Go to My Page</a>
                <% if (EmergencyAvailable)
                   { %>
                <span id="emergency-setup" class="emergency-inline" data-layout="inline" data-setup-label="Prepare emergency access"
                    data-api="<%: ResolveUrl("~/EmergencyApi.ashx") %>" data-csrf="<%: EmergencyCsrf %>" data-authenticator="<%: Kombit.Samples.CH.WebsiteDemo.EmergencyFeature.EmergencyWeb.Authenticator %>"
                    data-manage="<%: ResolveUrl("~/Emergency.aspx") %>" data-login="<%: ResolveUrl("~/login.ashx") + "?ReturnUrl=" + HttpUtility.UrlEncode(ResolveUrl("~/Default.aspx")) %>">
                    <span id="emergency-setup-text" class="emergency-inline-text"></span>
                    <span id="emergency-setup-actions"><button type="button" class="btn btn-default" disabled="disabled">Prepare emergency access</button></span>
                </span>
                <% } %>
                <% }
                   else
                   { %>
                <a href="MyPage.aspx" class="btn btn-info">Login to the app</a>
                <% } %>
            </div>
            <% if (EmergencyAvailable)
               { %>
            <p id="emergency-setup-status" class="login-alt-status emergency-inline-status" role="status" aria-live="polite" hidden="hidden"></p>
            <script type="text/javascript" src="<%: ((Kombit.Samples.CH.WebsiteDemo.sp)Master).AssetUrl("~/EmergencyAssets/setup.js") %>" defer="defer"></script>
            <% } %>
        </div>
    </div>
    <% if (string.IsNullOrEmpty(SAML20FederationConfig.GetConfig().Endpoints.MetadataLocation))
       { %>
    <div class="row">
        <div class="row-sm-height">
            <div class="col-md-12">
                <div class="div-metadata-error">
                    <h3><b>Metadata</b></h3>
                    The identity provider and the service provider must exchange metadata in order to establish SAML connections. 

                            You must add the <b>&lt;IDPEndPoints&gt;</b> tag to the <b>"<%= ConfigurationConstants.SectionNames.SAML20Federation %>"</b> section of the
                            application's configuration file in order to continue.
                </div>
            </div>
        </div>
    </div>
    <% }
       else if (certificateMissing)
       { %>
    <div class="row">
        <div class="row-sm-height">
            <div class="col-md-12">
                <div class="div-metadata-error">
                    <h3><b>Metadata</b></h3>
                    The identity provider and the service provider must exchange metadata in order to establish SAML connections. 

                            <div style="color: Red;">
                                The specified certificate could not be found. Please correct 
                            the certificate information in the "<%= ConfigurationConstants.SectionNames.Federation %>" section of the configuration file.
                            </div>
                </div>
            </div>
        </div>
    </div>
    <% }
       else
       { %>
    <div class="row">
        <div class="row-sm-height">
            <div class="col-md-9">
                <div class="div-metadata-path ">
                    <h3><b>Metadata</b></h3>
                    The identity provider and the service provider must exchange metadata in order to establish SAML connections. 
                            The Identity provider's metadata should be put in the directory 
                            <p><b>"<%= SAML20FederationConfig.GetConfig().Endpoints.MetadataLocation %>".</b></p>
                </div>
            </div>

            <div class="col-md-3">
                <div class="div-metadata-download">
                    <p>The metadata of the service provider can be downloaded </p>
                    <a href="metadata.ashx" class="btn btn-info" style="display: block; margin: 0 auto; width: 80px">here</a>
                </div>
            </div>
        </div>
    </div>

    <% } %>
</asp:Content>
