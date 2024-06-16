
## Attack Types
Burp Suite's Intruder tool supports several attack types, each designed for specific testing scenarios. Here’s a detailed explanation of each attack type:
### 1. **Sniper**

- **Description:** This is the simplest attack type, where Burp iterates through a single set of payloads, inserting each one at a single insertion point.
- **Use Case:** Useful for testing a single parameter or insertion point to see how different values affect the response.

### 2. **Battering Ram**

- **Description:** This attack type uses the same payload for all insertion points simultaneously. It iterates through the payload list and applies the same payload to every marked position.
- **Use Case:** Suitable for testing scenarios where the same input needs to be tested across multiple parameters, such as testing for reflected values in multiple places.

### 3. **Pitchfork**

- **Description:** In this type, each insertion point gets its own list of payloads, and Burp iterates through the payloads in parallel. It inserts the first payload from each list into the corresponding insertion point, then the second payload from each list, and so on.
- **Use Case:** Useful when you want to test combinations of inputs across multiple parameters. For example, testing pairs of usernames and passwords.

### 4. **Cluster Bomb**

- **Description:** This attack type is more complex, where Burp iterates through every possible combination of payloads from multiple lists. It inserts each combination into the corresponding insertion points.
- **Use Case:** Ideal for exhaustive testing of all possible payload combinations across multiple parameters, such as finding vulnerabilities that depend on specific parameter combinations.

### Summary Table:

|Attack Type|Description|Use Case|
|---|---|---|
|**Sniper**|Iterates through a single set of payloads for one insertion point|Testing a single parameter|
|**Battering Ram**|Uses the same payload for all insertion points simultaneously|Testing the same input across multiple parameters|
|**Pitchfork**|Iterates through payloads in parallel for multiple insertion points|Testing combinations of inputs across multiple parameters|
|**Cluster Bomb**|Iterates through all possible combinations of payloads from multiple lists|Exhaustive testing of all possible payload combinations|

## Payload Types
Burp Suite's Intruder tool offers several payload types, each designed for different kinds of automated attacks. Here’s a detailed explanation of each payload type:

### 1. **Simple List**

- **Description:** Allows you to provide a predefined list of payloads. You can either manually enter each payload or load them from a file.
- **Use Case:** Useful for testing with a specific set of known values, such as a list of usernames, passwords, or common SQL injection strings.

### 2. **Runtime File**

- **Description:** Reads payloads from a file at runtime. Each time an attack is executed, Burp reads the next payload from the specified file.
- **Use Case:** Ideal when dealing with very large lists of payloads that are impractical to load entirely into memory.

### 3. **Numbers**

- **Description:** Generates payloads based on a range of numbers. You can specify the start, end, and step values.
- **Use Case:** Useful for brute force attacks on numeric parameters, such as iterating through user IDs.

### 4. **Dates**

- **Description:** Generates payloads based on date ranges. You can specify the start date, end date, and the format of the dates.
- **Use Case:** Useful for testing date-based parameters, such as searching for events within a certain date range.

### 5. **Brute Forcer**

- **Description:** Generates payloads by iterating through a set of characters to create strings of increasing length.
- **Use Case:** Ideal for brute-forcing passwords or discovering hidden resources with predictable naming conventions.

### 6. **Character Substitutions**

- **Description:** Generates payloads by substituting characters in a base payload string according to a set of substitution rules.
- **Use Case:** Useful for testing input validation and escaping vulnerabilities, such as SQL injection or XSS.

### 7. **Illegal Unicode**

- **Description:** Generates payloads containing illegal Unicode characters.
- **Use Case:** Useful for testing how applications handle invalid Unicode input, which can lead to vulnerabilities like buffer overflow or improper input handling.

### 8. **Custom Iterator**

- **Description:** Allows you to define custom iterators to generate complex payloads. You can specify multiple iterators and their sequences.
- **Use Case:** Useful for generating payloads that require a specific combination of inputs.

### 9. **Extension-generated**

- **Description:** Generates payloads using Burp Suite extensions. These can be written in Java or Python using the Burp Extender API.
- **Use Case:** Useful for highly customized payload generation, tailored to specific testing needs that aren't covered by the default options.

### 10. **Markov Chains**

- **Description:** Generates payloads based on statistical models of character sequences. It uses a seed list to learn typical sequences and generate similar payloads.
- **Use Case:** Useful for generating realistic payloads based on observed patterns, such as usernames or paths.

### Summary Table:

|Payload Type|Description|Use Case|
|---|---|---|
|**Simple List**|Predefined list of payloads|Testing with specific known values|
|**Runtime File**|Reads payloads from a file at runtime|Handling large payload lists|
|**Numbers**|Generates numeric payloads|Brute force on numeric parameters|
|**Dates**|Generates date payloads|Testing date-based parameters|
|**Brute Forcer**|Iterates through characters to create strings|Brute-forcing passwords or discovering hidden resources|
|**Character Substitutions**|Substitutes characters in a base string according to rules|Testing input validation and escaping vulnerabilities|
|**Illegal Unicode**|Generates payloads with illegal Unicode characters|Testing handling of invalid Unicode input|
|**Custom Iterator**|Defines custom iterators for complex payload generation|Generating complex payloads requiring specific combinations|
|**Extension-generated**|Uses Burp extensions for payload generation|Customized payload generation|
|**Markov Chains**|Generates payloads based on statistical models of character sequences|Generating realistic payloads based on observed patterns|