module.exports = `# Contents of https://alice.example.com/work-groups
@prefix acl: <http://www.w3.org/ns/auth/acl#>.
@prefix vcard: <http://www.w3.org/2006/vcard/ns#> .
@prefix dct: <http://purl.org/dc/terms/>.
@prefix xsd: <http://www.w3.org/2001/XMLSchema#>.

<#this> a acl:GroupListing.

<#Accounting>
  a vcard:Group;
  vcard:hasUID <urn:uuid:8831CBAD-1111-2222-8563-F0F4787E5398:ABGroup>;
  dct:created "2013-09-11T07:18:19+0000"^^xsd:dateTime;
  dct:modified "2015-08-08T14:45:15+0000"^^xsd:dateTime;

  # Accounting group members:
  vcard:hasMember <https://bob.example.com/profile/card#me>;
  vcard:hasMember <https://candice.example.com/profile/card#me>.

<#Management>
  a vcard:Group;
  vcard:hasUID <urn:uuid:8831CBAD-3333-4444-8563-F0F4787E5398:ABGroup>;

  # Management group members:
  vcard:hasMember <https://deb.example.com/profile/card#me>.`
