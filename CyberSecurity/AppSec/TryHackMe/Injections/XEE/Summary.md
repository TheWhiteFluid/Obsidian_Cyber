**XXE (XML External Entity) injection** is a type of security flaw that exploits vulnerabilities in an application's XML input. It occurs when an application accepts XML input that includes external entity references within the XML itself. Attackers can leverage this vulnerability to disclose local files, make server-side requests, or execute remote code. 

XML (Extensible Markup Language) is a markup language derived from SGML (Standard Generalized Markup Language), which is the same standard that HTML is based on. XML is typically used by applications to store and transport data in a format that's both human-readable and machine-parseable. It's a flexible and widely used format for exchanging data between different systems and applications. XML consists of elements, attributes, and character data, which are used to represent data in a structured and organized way.

## XML Syntax and Structure
XML elements are represented by tags, which are surrounded by angle brackets (<>). Tags usually come in pairs, with the opening tag preceding the content and the closing tag following the content. For example:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<user id="1">
   <name>John</name>
   <age>30</age>
   <address>
      <street>123 Main St</street>
      <city>Anytown</city>
   </address>
</user>
```

The tag `<name>John</name>` represents an element named "name" with the content "John". Attributes provide additional information about elements and are specified within the opening tag. The tag `<user id="1">` specifies an attribute "id" with the value "1" for the element "user". Character data refers to the content within elements, such as "John".

The example above shows a simple XML document with elements, attributes, and character data. The tag `<?xml version="1.0" encoding="UTF-8"?>` declaration indicates the XML version, and the element contains various sub-elements and attributes representing user data.

## Common Use Cases in Web Applications
XML is widely used in web applications for data exchange, storage, and configuration. It's often used for web services and APIs, such as SOAP and REST, to exchange data between systems. XML is also used for configuration files, such as web server configurations or application settings.

## XSLT
XSLT (Extensible Stylesheet Language Transformations) is a language used to transform and format XML documents. While XSLT is primarily used for data transformation and formatting, it is also significantly relevant to XXE (XML External Entities) attacks.

XSLT can be used to facilitate XXE attacks in several ways:  
1. **Data Extraction**: XSLT can be used to extract sensitive data from an XML document, which can then be used in an XXE attack. For example, an XSLT stylesheet can extract user credentials or other sensitive information from an XML file.
2. **Entity Expansion**: XSLT can expand entities defined in an XML document, including external entities. This can allow an attacker to inject malicious entities, leading to an XXE vulnerability.
3. **Data Manipulation**: XSLT can manipulate data in an XML document, potentially allowing an attacker to inject malicious data or modify existing data to exploit an XXE vulnerability.
4. **Blind XXE**: XSLT can be used to perform blind XXE attacks, in which an attacker injects malicious entities without seeing the server's response.

## DTDs
DTDs or Document Type Definitions define the structure and constraints of an XML document. They specify the allowed elements, attributes, and relationships between them. DTDs can be internal within the XML document or external in a separate file.

Purpose and usage of DTDs:
- **Validation**: DTDs validate the structure of XML -  to ensure it meets specific criteria before processing, which is crucial in environments where data integrity is key.
- **Entity Declaration**: DTDs define entities that can be used throughout the XML document, including external entities which are key in XXE attacks.

Internal DTDs are specified using the `<!DOCTYPE` declaration, while external DTDs are referenced using the *SYSTEM* keyword.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE config [
<!ELEMENT config (database)>
<!ELEMENT database (username, password)>
<!ELEMENT username (#PCDATA)>
<!ELEMENT password (#PCDATA)>
]>
<config>
<!-- configuration data -->
</config>
```

The example above shows an internal DTD defining the structure of a configuration file. The `<!ELEMENT` declarations specify the allowed elements and their relationships. DTDs play a crucial role in XXE injection, as they can be used to declare external entities. External entities can reference external files or URLs, which can lead to malicious data or code injection.

## XML Entities
XML entities are placeholders for data or code that can be expanded within an XML document. There are five types of entities: internal entities, external entities, parameter entities, general entities, and character entities.

Example external entity:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!ENTITY external SYSTEM "http://example.com/test.dtd">
<config>
&external;
</config>
```

This shows an external entity referencing a URL. The `&external;` reference within the XML document will be expanded to the contents of the referenced URL.

### Internal entities
Internal Entities are essentially variables used within an XML document to define and substitute content that may be repeated multiple times. They are defined in the DTD (Document Type Definition) and can simplify the management of repetitive information. For example:
```xml
<!DOCTYPE note [
<!ENTITY inf "This is a test.">
]>
<note>
        <info>&inf;</info>
</note>
```

In this example, the `&inf;` entity is replaced by its value wherever it appears in the document.

### External entities
External Entities are similar to internal entities, but their contents are referenced from outside the XML document, such as from a separate file or URL. This feature can be exploited in XXE (XML External Entity) attacks if the XML processor is configured to resolve external entities. For example:
```xml
<!DOCTYPE note [
<!ENTITY external SYSTEM "http://example.com/external.dtd">
]>
<note>
        <info>&ext;</info>
</note>
```

Here, `&ext;` pulls content from the specified URL, which could be a security risk if the URL is controlled by an attacker.

### Parameter entities
Parameter Entities are special types of entities used within DTDs to define reusable structures or to include external DTD subsets. They are particularly useful for modularizing DTDs and for maintaining large-scale XML applications. For example:

```xml
<!DOCTYPE note [
<!ENTITY % common "CDATA">
<!ELEMENT name (%common;)>
]>
<note>
        <name>John Doe</name>
</note>
```

In this case, `%common;` is used within the DTD to define the type of data that the `name` element should contain.

### General entities
General Entities are similar to variables and can be declared either internally or externally. They are used to define substitutions that can be used within the body of the XML document. Unlike parameter entities, general entities are intended for use in the document content. For example:

```xml
<!DOCTYPE note [
<!ENTITY author "John Doe">
]>
<note>
        <writer>&author;</writer>
</note>
```

The entity `&author;` is a general entity used to substitute the author's name wherever it's referenced in the document.

### Character entities
Character Entities are used to represent special or reserved characters that cannot be used directly in XML documents. These entities prevent the parser from misinterpreting XML syntax. For example:

- `&lt;` for the less-than symbol (`<`)
- `&gt;` for the greater-than symbol (`>`)
- `&amp;` for the ampersand (`&`)

```xml
<note>
        <text>Use &lt; to represent a less-than symbol.</text>
</note>
```

This usage ensures that the special characters are processed correctly by the XML parser without breaking the document's structure.

### DOM Structure
The image below shows the type of entities in a DOM structure:
![](Pasted%20image%2020241218095112.png)
## XML Parsing
XML parsing is the process by which an XML file is read, and its information is accessed and manipulated by a software program. XML parsers convert data from XML format into a structure that a program can use (like a DOM tree). During this process, parsers may validate XML data against a schema or a DTD, ensuring the structure conforms to certain rules.

If a parser is configured to process external entities, it can lead to unauthorized access to files, internal systems, or external websites.

Several XML parsers are used across different programming environments; each parser may handle XML data differently, which can affect vulnerability to XXE injection.

- **DOM (Document Object Model) Parser**: This method builds the entire XML document into a memory-based tree structure, allowing random access to all parts of the document. It is resource-intensive but very flexible.
- **SAX (Simple API for XML) Parser**: Parses XML data sequentially without loading the whole document into memory, making it suitable for large XML files. However, it is less flexible for accessing XML data randomly.
- **StAX (Streaming API for XML) Parser**: Similar to SAX, StAX parses XML documents in a streaming fashion but gives the programmer more control over the XML parsing process.
- **XPath Parser**: Parses an XML document based on expression and is used extensively in conjunction with XSLT.