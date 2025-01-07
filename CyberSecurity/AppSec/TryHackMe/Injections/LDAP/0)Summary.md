LDAP, which stands for Lightweight Directory Access Protocol, is a widely used protocol for accessing and maintaining distributed directory information services over an Internet Protocol (IP) network. LDAP enables organizations to manage users centrally, as well as groups and other directory information, often used for authentication and authorization purposes in web and internal applications.

In LDAP, directory entries are structured as objects, each adhering to a specific schema that defines the rules and attributes applicable to the object. This object-oriented approach ensures consistency and governs how objects like users or groups can be represented and manipulated within the directory.

**Services that use LDAP**:
- **Microsoft Active Directory:** A service for Windows domain networks, utilizing LDAP as part of its underlying protocol suite to manage domain resources.
- **OpenLDAP:** An open-source implementation of LDAP, widely used for managing user information and supporting authentication mechanisms across various platforms.


## LDIF Format
LDAP entries can be represented using the LDAP Data Interchange Format (LDIF), a standard plain text data format for representing LDAP directory entries and update operations. LDIF imports and exports directory contents and describes directory modifications such as adding, modifying, or deleting entries.

## Structure
An LDAP directory follows a hierarchical structure like a file system's tree. This structure comprises various entries representing a unique item, such as a user, group, or resource.

At the top of the LDAP tree, we find the **top-level domain (TLD)**, such as `dc=ldap,dc=thm`. Beneath the TLD, there may be **subdomains** or **organizational units (OUs)**, such as `ou=people` or `ou=groups`, which further categorize the directory entries.
	![](Pasted%20image%2020250107052711.png)

- **Distinguished Names (DNs):** Serve as unique identifiers for each entry in the directory, specifying the path from the top of the LDAP tree to the entry, for example, `cn=John Doe,ou=people,dc=example,dc=com`.
- **Relative Distinguished Names (RDNs):** Represent individual levels within the directory hierarchy, such as `cn=John Doe`, where `cn` stands for Common Name.
- **Attributes:** Define the properties of directory entries, like `mail=john@example.com` for an email address.

  
## Search Queries
LDAP search queries are fundamental in interacting with LDAP directories, allowing you to locate and retrieve information stored within the directory. Understanding how to construct these queries is crucial for effectively utilizing LDAP services.

An LDAP search query consists of several components, each serving a specific function in the search operation:
1. **Base DN (Distinguished Name):** This is the search's starting point in the directory tree.
2. **Scope:** Defines how deep the search should go from the base DN. It can be one of the following:
    - `base` (search the base DN only),
    - `one` (search the immediate children of the base DN),
    - `sub` (search the base DN and all its descendants).
3. **Filter:** A criteria entry must match to be returned in the search results. It uses a specific syntax to define these criteria.
4. **Attributes:** Specifies which characteristics of the matching entries should be returned in the search results.

The basic syntax for an LDAP search query looks like this:

```default
(base DN) (scope) (filter) (attributes)
```

### Filters and Syntax
Filters are the core of LDAP search queries, defining the conditions that entries in the directory must meet to be included in the search results. The syntax for LDAP filters is defined in [RFC 4515](https://www.openldap.org/lists/ietf-ldapbis/200606/msg00010.html), where filters are represented as strings with a specific format, such as `(canonicalName=value)`. LDAP filters can use a variety of operators to refine search criteria, including equality (`=`), presence (`=*`), greater than (`>=`), and less than (`<=`).

One of the most essential operators in LDAP filters is the wildcard `*`, which signifies a match with any number of characters. This operator is crucial for formulating broad or partial-match search conditions.

**Simple Filter:**

This filter targets entries with a canonical name (`cn`) exactly matching "John Doe".
```default
(cn=John Doe)
```

**Wildcards:**

This filter applies the wildcard operator to match any entry where the `cn` begins with "J", regardless of what follows.
```php
(cn=J*)
```


**Complex Filters with Logical Operators:**
For a more complex search query, filters can be used with each other using logical operators such as AND (`&`), OR (`|`), and NOT (`!`). 

This filter searches for entries classified as "user" in their object class with a canonical name starting with either "John" or "Jane".
```default
(&(objectClass=user)(|(cn=John*)(cn=Jane*)))
```

This filter searches for entries classified as "user" in their object class with a canonical name starting with either "John" or "Jane".


While not commonly exposed directly, LDAP services can be accessible over the network via ports 389 (for unencrypted or StartTLS connections) and 636 (for SSL/TLS connections). When LDAP services are accessible publicly, tools such as `ldapsearch`, part of the OpenLDAP suite, can be used to interact with the LDAP server. This tool allows a user to query and modify the LDAP directory from the command line, making it a valuable resource for both legitimate administrative tasks and, potentially, for attackers exploiting LDAP Injection vulnerabilities. For example:

Sample Search Query using ldapsearch
```shell-session
user@tryhackme$ ldapsearch -x -H ldap://MACHINE_IP:389 -b "dc=ldap,dc=thm" "(ou=People)"
# extended LDIF
#
# LDAPv3
# base <dc=ldap,dc=thm> with scope subtree
# filter: (ou=People)
# requesting: ALL
#

# People, ldap.thm
dn: ou=People,dc=ldap,dc=thm
objectClass: organizationalUnit
objectClass: top
ou: People

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
```

This command uses `ldapsearch` to perform a search against an LDAP server located at the vulnerable machine on port 389, starting at the base DN `dc=ldap,dc=thm` and using a filter that will search for entries under the organizational unit of People.