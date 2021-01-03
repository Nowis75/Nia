<?php
//error_reporting(E_ERROR);
session_start();
//require "admin/inc/config.inc.php";
//require "admin/inc/_func.php";
//require "inc/ini.php";

$cfg['niaCert']='assets/vendor/saml/certs/tnia.crt';
$cfg['niaPrimKey']='assets/vendor/saml/certs/sp.key';

require 'assets/vendor/saml/vendor/autoload.php';
require 'assets/vendor/saml/vendor/saml/NiaContainer.php';
require 'assets/vendor/saml/vendor/saml/NiaServiceProvider.php';
require 'assets/vendor/saml/vendor/saml/NiaExtensions.php';

use SAML2\Assertion;
use SAML2\Certificate\Key;
use SAML2\EncryptedAssertion;
use SAML2\LogoutRequest;
use SAML2\XML\Chunk;
use SAML2\XML\ds\KeyInfo;
use SAML2\XML\ds\X509Certificate;
use SAML2\XML\ds\X509Data;
use SAML2\XML\md\ContactPerson;
use SAML2\XML\md\EntityDescriptor;
use SAML2\DOMDocumentFactory;
use SAML2\Constants;
use SAML2\XML\md\IDPSSODescriptor;
use SAML2\Compat\ContainerSingleton;
use SAML2\AuthnRequest;
use SAML2\Response;
use SAML2\XML\md\IndexedEndpointType;
use SAML2\XML\md\KeyDescriptor;
use SAML2\XML\md\Organization;
use SAML2\XML\md\SPSSODescriptor;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;


function generateSePMetadata()
{
    $service_provider = new NiaServiceProvider();
    $nia_container = new NiaContainer();
    ContainerSingleton::setContainer($nia_container);

    $descriptor = new EntityDescriptor();

    // kontaktni osoba neni vyzadovana
    $contact = new ContactPerson();
    $contact->setContactType('technical');
    $contact->setCompany('Paropisek');
    $contact->setGivenName('Milan');
    $contact->setSurName('Novak');
    $contact->setEmailAddress(['novak@voxcafe.cz']);

    // Organizace neni vyzadovana
    $org = new Organization();
    $org->setOrganizationDisplayName(['cz' => 'Paropisek']);
    $org->setOrganizationName(['cz' => 'Paropisek']);
    $org->setOrganizationURL(['cz' => 'https://www.paropisek.cz']);

    $local_cert_x509_cert = new X509Certificate();
    $local_cert_x509_cert->setCertificate($service_provider->getCertificateData());
    $local_cert_x509_data = new X509Data();
    $local_cert_x509_data->setData([$local_cert_x509_cert]);

    $key_info = new KeyInfo();
    $key_info->addInfo($local_cert_x509_data);

    $sign_key_descriptor = new KeyDescriptor();
    $sign_key_descriptor->setUse(Key::USAGE_SIGNING);
    $sign_key_descriptor->setKeyInfo($key_info);

    $enc_key_descriptor = new KeyDescriptor();
    $enc_key_descriptor->setUse(Key::USAGE_ENCRYPTION);
    $enc_key_descriptor->setKeyInfo($key_info);

    $doc = DOMDocumentFactory::create();
    $enc_method_dom = $doc->createElementNS('urn:oasis:names:tc:SAML:2.0:metadata', 'EncryptionMethod');
    $enc_method_dom->setAttribute('Algorithm', XMLSecurityKey::AES256_CBC);
    $enc_method = new Chunk($enc_method_dom);

    $enc_key_descriptor->setEncryptionMethod([$enc_method]);

    $acs = new IndexedEndpointType();
    $acs->setIsDefault(true);
    $acs->setBinding(Constants::BINDING_HTTP_POST);
    $acs->setIndex(1);
    $acs->setLocation('https://www.paropisek.cz/sepapp.php');

    $spsso = new SPSSODescriptor();
    $spsso->setAuthnRequestsSigned(true);
    $spsso->setWantAssertionsSigned(true);
    $spsso->addProtocolSupportEnumeration('urn:oasis:names:tc:SAML:2.0:protocol');
    $spsso->addKeyDescriptor($sign_key_descriptor);
    $spsso->addKeyDescriptor($enc_key_descriptor);
    $spsso->setOrganization($org);
    $spsso->addContactPerson($contact);
    $spsso->addAssertionConsumerService($acs);
    $spsso->setNameIDFormat([
        Constants::NAMEFORMAT_BASIC,
        Constants::NAMEFORMAT_UNSPECIFIED,
        Constants::NAMEFORMAT_URI
    ]);

    $descriptor->addRoleDescriptor($spsso);

    $descriptor->setID($nia_container->generateId());
    $descriptor->setEntityID($service_provider->getEntityId());
    $descriptor->setValidUntil(strtotime('next monday', strtotime('tomorrow')));

    $metadata_dom = $descriptor->toXML();

    $extensions = $metadata_dom->ownerDocument->createElementNS('urn:oasis:names:tc:SAML:2.0:metadata', 'md:Extensions');
    $sptype = $metadata_dom->ownerDocument->createElementNS('http://eidas.europa.eu/saml-extensions', 'eidas:SPType');
    $sptype->nodeValue = 'public';
    $extensions->appendChild($sptype);
    $digest_method = $metadata_dom->ownerDocument->createElementNS('urn:oasis:names:tc:SAML:metadata:algsupport', 'alg:DigestMethod');
    $digest_method->setAttribute('Algorithm', XMLSecurityDSig::SHA256);
    $extensions->appendChild($digest_method);
    $signing_method = $metadata_dom->ownerDocument->createElementNS('urn:oasis:names:tc:SAML:metadata:algsupport', 'alg:SigningMethod');
    $signing_method->setAttribute('MinKeySize', 256);
    $signing_method->setAttribute('Algorithm', XMLSecurityKey::RSA_SHA256);
    $extensions->appendChild($signing_method);

    $metadata_dom->appendChild($extensions);

    $metadata_dom_signed = $service_provider->insertSignature($metadata_dom);       // podepsany Metadat

    $xmlResult=$metadata_dom_signed->ownerDocument->saveXML();                      // primy XML

    return $xmlResult;
}

function extractSSOLoginUrls(EntityDescriptor $idp_descriptor){
    $idp_sso_descriptor = false;
    foreach ($idp_descriptor->getRoleDescriptor() as $role_descriptor) {
        if ($role_descriptor instanceof IDPSSODescriptor) {
            $idp_sso_descriptor = $role_descriptor;
        }
    }

    $sso_redirect_login_url = false;
    $sso_post_login_url = false;

    if ($idp_sso_descriptor instanceof IDPSSODescriptor) {
        foreach ($idp_sso_descriptor->getSingleSignOnService() as $descriptorType) {
            if ($descriptorType->getBinding() === Constants::BINDING_HTTP_REDIRECT) {
                $sso_redirect_login_url = $descriptorType->getLocation();
            } else if ($descriptorType->getBinding() === Constants::BINDING_HTTP_POST) {
                $sso_post_login_url = $descriptorType->getLocation();
            }
        }
    }

    return [Constants::BINDING_HTTP_REDIRECT => $sso_redirect_login_url, Constants::BINDING_HTTP_POST => $sso_post_login_url];
}

function extractSSOLogoutUrls(EntityDescriptor $idp_descriptor){
    $idp_sso_descriptor = false;
    foreach ($idp_descriptor->getRoleDescriptor() as $role_descriptor) {
        if ($role_descriptor instanceof IDPSSODescriptor) {
            $idp_sso_descriptor = $role_descriptor;
        }
    }
    $sso_redirect_logout_url = false;
    $sso_post_logout_url = false;

    if ($idp_sso_descriptor instanceof IDPSSODescriptor) {
        foreach ($idp_sso_descriptor->getSingleLogoutService() as $descriptorType) {
            if ($descriptorType->getBinding() === Constants::BINDING_HTTP_REDIRECT) {
                $sso_redirect_logout_url = $descriptorType->getLocation();
            } else if ($descriptorType->getBinding() === Constants::BINDING_HTTP_POST) {
                $sso_post_logout_url = $descriptorType->getLocation();
            }
        }
    }

    return [Constants::BINDING_HTTP_REDIRECT => $sso_redirect_logout_url, Constants::BINDING_HTTP_POST => $sso_post_logout_url];
}

function generateLogoutRequest(EntityDescriptor $idp_descriptor, Assertion $assertion){
    $service_provider = new NiaServiceProvider();
    $nia_container = new NiaContainer();
    ContainerSingleton::setContainer($nia_container);

    $urls = extractSSOLogoutUrls($idp_descriptor);
    $logout_redirect_url = $urls[Constants::BINDING_HTTP_REDIRECT];

    $logout_request = new LogoutRequest();
    $logout_request->setSessionIndex($assertion->getSessionIndex());
    $logout_request->setDestination($logout_redirect_url);
    $logout_request->setId($nia_container->generateId());
    $logout_request->setIssueInstant(time());
    $logout_request->setIssuer($nia_container->getIssuer());
    $logout_request->setNameId($assertion->getNameId());

    $logout_xml_dom = $logout_request->toUnsignedXML();
    $logout_xml_dom = $service_provider->insertSignature($logout_xml_dom, false);

    return $logout_xml_dom;
}

function getIdpDescriptor(){
    $metadata_string = getIdpMetadataContents();
    $metadata_dom = DOMDocumentFactory::fromString($metadata_string);
    try {
        return new EntityDescriptor($metadata_dom->documentElement);
    } catch (Exception $e) {
        $this->Flash->error($e->getMessage());
    }
    return false;
}

function getIdpMetadataContents(){
    $idp_metadata_url = 'https://tnia.eidentita.cz/FPSTS/FederationMetadata/2007-06/FederationMetadata.xml';
    $idp_metadata_contents = file_get_contents($idp_metadata_url);
    return $idp_metadata_contents;
}

function generateAuthnRequest(EntityDescriptor $idp_descriptor){

    $nia_container = new NiaContainer();
    $service_provider = new NiaServiceProvider();
    ContainerSingleton::setContainer($nia_container);

    $urls = extractSSOLoginUrls($idp_descriptor);                                   // získání url adresy, na kterou přesměrovat uživatele při metodě HTTP-REDIRECT
    $sso_redirect_login_url = $urls[Constants::BINDING_HTTP_REDIRECT];
    $auth_request = new AuthnRequest();                                             // samotný AuthnRequest
    $auth_request->setId($nia_container->generateId());                             // unikátní ID
    $auth_request->setIssuer($nia_container->getIssuer());                          // Issuer, neboli "Unikátní URL adresa zabezpečené části Vašeho webu"
    $auth_request->setDestination($sso_redirect_login_url);                         // explicitní deklarace příjemce zprávy
    $auth_request->setAssertionConsumerServiceURL(NiaServiceProvider::$AssertionConsumerServiceURL); // adresa kam se má uživatel přesměrovat při dokončení procesu na straně IdP
    // vyžadovaná úroveň ověření identity
    // LOW dovoluje využít NIA jméno+heslo+sms, stejně jako datovou schránku FO nebo identitu zahraničního občana
    // SUBSTANTIAL pak dovoluje méně variant
    // HIGH dovoluje pouze elektronický občanský průkaz
    $auth_request->setRequestedAuthnContext([
        'AuthnContextClassRef' => [NiaServiceProvider::LOA_LOW],
        'Comparison' => 'minimum'
    ]);

    $auth_request_xml_domelement = $auth_request->toUnsignedXML();                  // vygenerování nepodepsaného požadavku
    $exts = new NiaExtensions($auth_request_xml_domelement);                        // přidání vyžadovaných atributů (informací o uživateli), element samlp:Extensions
    $exts->addAllDefaultAttributes();
    $auth_request_xml_domelement = $exts->toXML();
    $auth_request_xml = $auth_request_xml_domelement->ownerDocument->saveXML($auth_request_xml_domelement);
    $auth_request_xml_domelement = DOMDocumentFactory::fromString($auth_request_xml);
    $auth_request_xml_domelement = $service_provider->insertSignature($auth_request_xml_domelement->documentElement);   // vložení vlastního podpisu naším privátním klíčem

    return $auth_request_xml_domelement;
}

$metadata_string = getIdpMetadataContents();
$metadata_dom = DOMDocumentFactory::fromString($metadata_string);
$metadata = new EntityDescriptor($metadata_dom->documentElement);                   // také lze využít metodu DOMDocumentFactory::fromFile($filepath); pokud jsou metadata stažena lokálně

switch($_GET['action']){
    case "getToken":        // Ziskani tokenu po prihlaseni a dat uzivatele

        $authn_request = generateAuthnRequest($metadata);

        $tnia_public_key = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, ['type' => 'public']);
        $tnia_public_key->loadKey(file_get_contents($cfg['niaCert']), false, true);     // certifikat NIA

        if (!$_POST['SAMLResponse']) {                                                      // pokud není přítomna odpověď
            exit("Chybí odpověď v POST datech");
        }


        $post_raw = $_POST['SAMLResponse'];                                                 // získání z POST dat
        $post_raw = base64_decode($post_raw, true /* striktní validace base64 */);    // dekódování

        if ($post_raw === false) {                                                          // pokud data nejsou platně dekódována base64
           exit("Data nejsou validní Base64");
        }

        try {
            $post_dom = DOMDocumentFactory::fromString($post_raw);
        } catch (\Exception $e) {
            // UnparseableXmlException pokud data nejsou kompletní nebo nejsou validní XML
            // RuntimeException pokud je v datech neočekávaný obsah
            exit("Data nejsou platným XML");
        }

        $response = new Response($post_dom->documentElement);

        try {
           if (!$response->validate($tnia_public_key)) {
               // false je pokud není žádný dostupný validátor
               exit("Není možné zkontrolovat podpis odpovědi");
            }
        } catch (\Exception $e) {
            // vyjímka bude první vyjímkou z potenciálně mnoha, která popisuje, proč podpis dokumentu není validní dle
            // daného veřejného klíče
            exit("Neplatný XML podpis");
        }

        $local_private_key = new XMLSecurityKey(XMLSecurityKey::RSA_OAEP_MGF1P, ['type' => 'private']);            // konstanta RSA_OAEP_MGF1P definuje algoritmus, který NIA využívá při XML přenosu šifrované odpovědi
        $local_private_key->loadKey(file_get_contents($cfg['niaPrimKey']), false, false);                   // načtení privátního klíči k certifikátu, kterým byla podesaná žádost o autorizaci (saml:AuthnRequest)

        $assertions = $response->getAssertions();                                       // získání přítomných autorizací

        $encrypted_assertion = false;
        try {

            foreach ($assertions as $a) {
                if ($a instanceof EncryptedAssertion) {
                    $encrypted_assertion = $a->getAssertion($local_private_key);        // získání dešifrované Assertion z objektu EncryptedAssertion
                    $assertion_dom = $encrypted_assertion->toXML();

                    $assertion_dom->ownerDocument->preserveWhiteSpace = false;
                    $assertion_dom->ownerDocument->formatOutput = true;

                    $assertion_xml = $assertion_dom->ownerDocument->saveXML();

                    $attributes = $encrypted_assertion->getAttributes();
                    $current_address_key = "http://eidas.europa.eu/attributes/naturalperson/CurrentAddress";
                    $current_address_raw = isset($attributes[$current_address_key]) ? base64_decode(reset($attributes[$current_address_key])) : false;

                    $tradresaid_key = "http://schemas.eidentita.cz/moris/2016/identity/claims/tradresaid";
                    $tradresaid_raw = isset($attributes[$tradresaid_key]) ? base64_decode(reset($attributes[$tradresaid_key])) : false;

                    $idp_descriptor = getIdpDescriptor();
                    $logout_url = extractSSOLogoutUrls($idp_descriptor)[Constants::BINDING_HTTP_REDIRECT];
                    $logout_request = generateLogoutRequest($idp_descriptor, $encrypted_assertion);
                    $logout_request->ownerDocument->preserveWhiteSpace = false;
                    $logout_request->ownerDocument->formatOutput = true;
                    $logout_request_xml_string = $logout_request->ownerDocument->saveXML();
                    /*
                    echo "<hr><pre>";
                    print_r($logout_request_xml_string);
                    echo "<hr></pre>";
                    */
                    $logout_request_encoded = gzdeflate($logout_request_xml_string);
                    $logout_request_encoded = base64_encode($logout_request_encoded);
                    $logout_request_encoded = urlencode($logout_request_encoded);

                    // získání URL adresy pro Logout
                    $final_logout_url = $logout_url . '?SAMLRequest=' . $logout_request_encoded;

                }
            }


        } catch (\Exception $e) {
            exit("Nastala chyba při dešifrování XML");
        }

        if (!$encrypted_assertion) {                                                    // pokud nebyla nalezena žádná uživatelská identifikace
            exit("V datech chybí identifikace uživatele");
        }


        echo "<a href=\"$final_logout_url\">LOGOUT</a>";

        // ------------- PARSE DATA OUT------------
        echo "<h2>EIDAS current address</h2>";
        $xml = simplexml_load_string("<eidas>".str_replace("eidas:","",$current_address_raw)."</eidas>");

        echo "Posta mesto: ".$xml->PostName[0]."<br>";
        echo "Psc: ".$xml->PostCode[0]."<br>";
        echo "Mesto: ".$xml->CvaddressArea[0]."<br>";


        echo "<pre>";
        print_r($current_address_raw);                                                  // deokodovana adresa
        echo "</pre>";


        echo "<h2>Extract data from response XML</h2>";
        echo "Jmeno: ".$attributes['http://eidas.europa.eu/attributes/naturalperson/CurrentGivenName'][0]."<br>";
        echo "Prijmeni: ".$attributes['http://eidas.europa.eu/attributes/naturalperson/CurrentFamilyName'][0]."<br>";
        echo "Email: ".$attributes['http://www.stork.gov.eu/1.0/eMail'][0]."<br>";
        echo "Datum nar.: ".$attributes['http://eidas.europa.eu/attributes/naturalperson/DateOfBirth'][0]."<br>";
        echo "Vek: ".$attributes['http://www.stork.gov.eu/1.0/age'][0]."<br>";
        echo "Starsi jak 18: ".$attributes['http://www.stork.gov.eu/1.0/isAgeOver'][0]."<br>";
        echo "Identifikace: ".$attributes['http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier'][0]."<br>";

        echo "<h2>NIA sign all object data</h2>";
        echo "<pre>";
        print_r($encrypted_assertion);
        echo "</pre>";

    break;

    case "getSepMeta":
       header("Content-type: text/xml");
      // echo "<pre>";
       print_r(generateSePMetadata());
      // echo "</pre>";

    break;

    default:        // Vytvoreni odkazu na prihlaseni IdP

        $tnia_cert_data = file_get_contents($cfg['niaCert']);                                       // soubor s certifikátem bychom měli mít uložen lokálně, aby validace podpisu proběhla korektně
                                                                                                    // na uvedené adrese je uložen NIA certifikát (PEM) z testovacího prostředí
        $tnia_key = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, ['type' => 'public']);      // z dat certifikátu vytvoříme klíč
        $tnia_key->loadKey($tnia_cert_data, false, true);

        $valid = $metadata->validate($tnia_key);                                                    // a použijeme interní metodu EntityDescriptor->validate(XMLSecurityKey $key) pro validaci

        $urls = extractSSOLoginUrls($metadata);         // Array - adresy na NIA
        $redirect_url = $urls[Constants::BINDING_HTTP_REDIRECT];
        $post_url = $urls[Constants::BINDING_HTTP_POST];

        $authn_request = generateAuthnRequest($metadata);                                           // EntityDescriptor pro IdP
                                                                                                    // $idp_descriptor = generateIdpDescriptor();
        $xml = $authn_request->ownerDocument->saveXML();                                            // komprese a enkódování požadavku

        /*
        echo "<pre>";
        print_r($xml);
        echo "</pre>";
        */

        $query = gzdeflate($xml);
        $query = base64_encode($query);
        $query = urlencode($query);

        // získání URL adresy pro prihlaseni
        $final_url = $redirect_url . (parse_url($redirect_url, PHP_URL_QUERY) ? '&' : '?') . 'SAMLRequest=' . $query;

        echo "<a href=\"{$final_url}\" target=\"_blank\">LOGIN</a><br>";
        echo "<a href=\"?action=getSepMeta\" target=\"_blank\">GENEROVANI SeP METADAT</a><br>";

    break;

}




