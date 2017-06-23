---
title: Reference - Policies
layout: page
---

{% include toc.md key='introduction' %}

Conjur is managed primarily through policies. A policy is a [YAML](http://yaml.org) document which describes users, groups, hosts, layers, web services, and variables, plus role-based access control grants and privileges. Once you've loaded a policy into Conjur, you can use the Conjur API to authenticate as a role, list and search the entities in the policy, perform permission checks, store and fetch secrets, etc.

Conjur's YAML syntax is easy for both humans and computers to read and write. Here's a typical policy which defines users, groups, and a policy for the application "myapp". 

{% include policy-file.md policy='tour' %}

Some key features of this policy:

* There is 1 Variable (secret) which is a database password.
* There is one Host (a host is a job, container, server, or VM).
* The host belongs to a Layer.
* The Layer can read and execute (fetch), but not update the database secrets.
* A Host Factory can be used to dynamically create new hosts in the layer.
* Annotations help to explain the purpose of each statement in the policy.

{% include toc.md key='rbac' %}

Conjur implements role-based access control (RBAC) to provide role management and permission checking. In RBAC, a permission check is called a "transaction". Each transaction has three parts:

1. **the role** who, or what, is acting. In Conjur, individual entities such as users and hosts are roles, and groups-of-entities such as groups and layers are roles too.
2. **the privilege** the name of an action which the role is attempting to perform. In Conjur, privileges generally follow the Unix pattern of `read`, `execute` and `update`. 
3. **the resource** the protected thing, such as a secret or a webservice.

RBAC determines whether a transaction is allowed or denied by traversing the roles and permissions in the policies. Transactions are always denied by default, and only allowed if the privilege is granted to some role (e.g. a Layer) of the current authenticated role (e.g. a Host).

In the example above, the `permit` statement in the "db" policy instructs Conjur RBAC to allow some transactions:

* role: `group:db/secrets-users`
* privilege: `read` and `execute`
* resource: all variables in the "db" policy

Permissions are also available via ownership. Each object in Conjur has an owner, and the owner always have full privileges on the object. 

By default, when a policy is created, the policy is owned by the current authenticated user who is creating the policy. Objects inside a policy are owned by the policy (which is a kind of role), so the current authenticated user's ownership of the policy is transitive to all the objects in the policy.

{% include toc.md key='loading' %}

Conjur policies are loaded through the CLI using the command `conjur policy load`. This command requires two arguments:

* `policy-id` An identifier for the policy. The first time you load a policy, use the policy id "bootstrap". This is a special policy name that is used to define root-level data. The "bootstrap" policy may define sub-policies, initially empty, which you can later populate with their own data. Aside from the "bootstrap" policy, policy ids are not valid until the corresponding policy has been created.
* `policy-file` Policy file containing statements in YAML format. Use a single dash `-` to read the policy from STDIN.

Here's how to load the policy "conjur.yml":

{% highlight shell %}
$ conjur policy load bootstrap conjur.yml
Policy loaded
TODO: Show additional command output
{% endhighlight %}

{% include toc.md key='history' %}

When you load a policy, the policy YAML is stored in the Conjur Server. As you make updates to the policy, the subsequent versions of policy YAML are stored as well. This policy history is available by fetching the `policy` resource. For example, using the CLI:

TODO: verify this

{% highlight shell %}
$ conjur show policy:frontend
{
TODO: fill out this example
... bunch of JSON including embedded YAML
}
{% endhighlight %}

{% include toc.md key='loading-modes' %}

The server supports three different modes for loading a policy : **POST**, **PATCH**, and **PUT**.

### POST Mode

In **POST** mode, the server will only create new data. If the policy contains deletion statements, such as `!delete`, `!revoke`, or `!deny`, it's an error.

If there are objects that already exist in the server but are not specified in the policy, those objects are left alone.

#### Permission Required

The client must have `create` privilege on the policy.

### PATCH Mode

In **PATCH** mode, the server will both create and delete data. 

Objects and grants that already exist in the server but are not specified in the policy will be left alone.

#### Permission Required

The client must have `update` privilege on the policy.

### PUT Mode

In **PUT** mode, the data in the server will be replaced with the data specified in the policy. 

Objects and grants that exist in the server but aren't specified in the policy will be deleted. 

#### Permission Required

The client must have `update` privilege on the policy.

{% include toc.md key='delegation' %}

An API call which attempts to modify a policy requires `create` (for **POST**) or `update` (for **PUT** and **PATCH**) privilege on the affected policy.

These permission rules can be leveraged to delegate management of the Conjur policy system across many team members.

When a Conjur account is created, an empty "bootstrap" policy is created by default. This policy is owned by the `admin` user of the account. As the owner, the `admin` user has full permissions on the "bootstrap" policy. 

A policy document can define policies within it. For example, if the "bootstrap" policy is:

{% include policy-file.md policy='policy-reference-root-example' %}

Then two new policies will be created: "db" and "frontend". The account "admin" user will own these policies as well, since no explicit owner was specified.

To delegate ownership of policies, create user groups and assign those groups as policy owners:

{% include policy-file.md policy='policy-reference-root-example-ownership' %}

Now the user groups you defined will have ownership (and full management privileges) over the corresponding policies. For example, a member of "frontend-developers" will be able to make any change to the "frontend" policy, but will be forbidden from modifying the "bootstrap" and "db" policies.

`!permit` statements can also be used to manage policy permissions in a more granular way. Here's how to allow a user group to `read` and `create`, but not `update`, a policy:

{% include policy-file.md policy='policy-reference-root-example-permissions' %}

With this policy, the "frontend-developers" group will be allowed to **GET** and **POST** the policy, but not to **PUT** or **PATCH** it.

{% include toc.md key='statement-reference' %}

This section describes in detail the syntax of the policy YAML.

### Common attributes

Some attributes are common across multiple entities:

* **id** An identifier which is unique to the kind of entity (`user`, `host`, `variable`, etc). By convention, Conjur ids are path-based. For example: `prod/webservers`. Each record in Conjur is uniquely identified by `account:kind:id`.
* **owner** A role having all privileges on the thing it's applied to. For example, if a role `group:frontend` is the owner of a secret, then the group and all of its members can perform any action on the secret. Normally, the `owner` attribute is only needed in the bootstrap policy.

{% include toc.md key='statement-reference' section='policy' %}

A policy is used to organize a common set of records and permissions grants into a common namespace (`id` prefix).

The `body` element of a policy lists the entities and grants that are part of the policy. Each entity in the policy inherits the id of the policy; for example, a variable named `db-password` in a policy named `prod/myapp` would have a fully-qualified id `prod/myapp/db-password`. In addition, all the entities in the body of the policy are owned by the policy. Therefore, the owner of a policy implicitly owns everything defined in the policy. This nested ownership makes it possible to delegate the management of a complex system to many different teams and groups, each with responsibility over a small set of policies. 

#### Example

{% highlight yaml %}
- !policy
  id: prod
  body:
  - !policy
    id: webserver
    body:
    - &secrets
      - !variable ssl/private-key

    - !layer

    - !grant
      role: !layer
      permissions: [ read, execute ]
      resources: *secrets
{% endhighlight %}

{% include toc.md key='statement-reference' section='user' %}

A human user. For servers, VMs, scripts, PaaS applications, and other code actors, create hosts instead of users.

Users can authenticate using their `id` as the login and their API key as the credential. When a new user is created, it's assigned a randomly generated API key. The API key can be reset (rotated) by an administrative user if it is lost or compromised. 

Users can also be assigned a password. A user can use her password to `login` and obtain her API key, which can be used to authenticate as described above. Further details on login and authentication are provided in the API documentation.

#### Attributes

* **id** Should not contain special characters such as `:/`. It may contain the `@` symbol.
* **public_keys** Stores public keys for the user, which can be retrieved through the public keys API.

#### Example

{% highlight yaml %}
- !user
  id: kevin
  public_keys:
  - ssh-rsa AAAAB3NzaC1yc2EAAAAD...+10trhK5Pt kgilpin@laptop

- !group
  id: ops

- !grant
  role: !group ops
  member: !user kevin
{% endhighlight %}

{% include toc.md key='statement-reference' section='group' %}

A group of users and other groups. Layers can also be added to groups, in order to give applications the privileges of the group (such as access to secrets).

When a user becomes a member of a group they are granted the group role, and inherit the group’s privileges. Groups can also be members of groups; in this way, groups can be organized and nested in a hierarchy.

#### Attributes

* **id**

#### Example

{% highlight yaml %}
- !user alice

- !user bob

- !group
  id: everyone
  annotations:
    description: All users belong to this group.

- !group
  id: ops
  annotations:
    description: This group is for production operational personnel.

- !grant
    role: !group ops
    members:
    - !user alice
    - !user bob
    
- !grant
    role: !group everyone
    member: !group ops
{% endhighlight %}

{% include toc.md key='statement-reference' section='host' %}

A server, VM, script, job, or container, or any other type of coded or automated actor.

Hosts defined in a policy are generally long-lasting hosts, and assigned to a
layer through a `!grant` entitlement. Assignment to layers is the primary way
for hosts to get privileges, such as access to variables.

Hosts can authenticate using `host/<id>` as the login and their API key as the credential. When a new host is created, it's assigned a randomly generated API key. The API key can be reset (rotated) by an administrative user if it is lost or compromised. 

#### Attributes

* **id**

#### Example

{% highlight yaml %}
- !layer webservers

- !host
  id: www-01
  annotations:
    description: Hypertext web server
        
- !grant
  role: !layer webservers
  member: !host www-01
{% endhighlight %}

{% include toc.md key='statement-reference' section='layer' %}

Host are organized into roles called "layers" (sometimes known in some other systems as "host groups"). Layers map logically to the groups of machines and code in your infrastructure. For example, a group of servers or VMs can be a layer; a cluster of containers which are performing the same function (e.g. running the same image) can also be modeled as a layer; a script which is deployed to a server can be a layer; an application which is deployed to a PaaS can also be a layer. Layers can be used to organize your system into broad permission groups, such as `dev`, `ci`, and `prod`, and for granular organization such as `dev/frontend` and `prod/database`.

Using layers to model the privileges of code helps to separate the permissions from the physical implementation of the application. For example, if an application is migrated from a PaaS to a container cluster, the logical layers that compose the application (web servers, app servers, database tier, cache, message queue) can remain the same. Also, layers are not tied to a physical location. If an application is deployed to multiple clouds or data centers, all the servers, containers and VMs can belong to the same layer.

#### Example

{% highlight yaml %}
- !layer prod/database

- !layer prod/app

- !host db-01
- !host app-01
- !host app-02

- !grant
  role: !layer prod/database
  member: !host db-01

- !grant
  role: !layer prod/app
  members:
  - !host app-01
  - !host app-02
{% endhighlight %}

{% include toc.md key='statement-reference' section='variable' %}

A variable provides encrypted, access-controlled storage and retrieval of arbitrary data values. Variable values are also versioned. The last 20 historical versions of the variable are available through the API; the latest version is returned by default.

Values are encrypted using aes-256-gcm. The encryption used in Conjur has been independently verified by a professional, paid cryptographic auditor.

#### Attributes

* **id**
* **kind** (string) Assigns a descriptive kind to the variable, such as 'password' or 'SSL private key'.
* **mime_type** (string) The expected MIME type of the values. This attribute is used to set the Content-Type header on HTTP responses.

#### Privileges

* **read** Permission to view the variable's metadata (e.g. annotations).
* **execute** Permission to fetch the default value or any historical value.
* **update** Permission to add a new value.

Note that `read`, `execute` and `update` are separate privileges. Having `execute` privilege does not confer `read`; nor does `update` confer `execute`.

#### Example

{% highlight yaml %}
- &variables
  - !variable
    id: db-password
    kind: password

  - !variable
    id: ssl/private_key
    kind: SSL private key
    mime_type: application/x-pem-file

- !layer app

- !permit
  role: !layer app
  privileges: [ read, execute ]
  resources: *variables
{% endhighlight %}

{% include toc.md key='statement-reference' section='webservice' %}

Represents a web service endpoint, typically an HTTP(S) service.

Permission grants are straightforward: an input HTTP request path is mapped to a webservice resource id. The HTTP method is mapped to an RBAC privilege. A permission check is performed, according to the following transaction:

* **role** client role on the HTTP request. The client can be obtained from an Authorization header (e.g. signed access token), or from the subject name of an SSL client certificate.
* **privilege** typically `read` for read-only HTTP methods, and `update` for POST, PUT and PATCH.
* **resource** web service resource id

#### Example

{% highlight yaml %}
- !group analysts

- !webservice
  id: analytics

- !permit
  role: !group analysts
  privilege: read
  resource: !webservice analytics
{% endhighlight %}

{% include toc.md key='statement-reference' section='entitlements' %}

Entitlements are role and privilege grants. `grant` is used to grant a `role` to a `member`. `permit` is used to give a `privilege` on a `role` to a resource.

Entitlements provide the "glue" between policies, creating permission relationships between different roles and subsystems. For example, a policy for an application may define a `secrets-managers` group which can administer the secrets in the policy. An entitlement will grant the policy-specific `secrets-managers` group to a global organizational group such as `operations` or `people/teams/frontend`.

{% include toc.md key='statement-reference' section='grant' %}

Grants one role to another. When role A is granted to role B, then role B is said to "have" role A. The set of all memberships of role B will include A. The set of direct members of role A will include role B.

If the role is granted with `admin` option, then the grantee (role B), in addition to having the role, can also grant and revoke the role to other roles.

A limitation on role grants is that there cannot be any cycles in the role graph. For example, if role A is granted to role B, then role B cannot be granted to role A.

Users, groups, hosts, and layers are roles, which means they can be granted to and revoked from each other.

The `role` must be defined in the same policy as the `!grant`. The `member` can be defined in any policy.

#### Example

{% highlight yaml %}
- !user alice

- !group operations
    
- !group development
  
- !group everyone

- !grant
  role: !group operations
  member: !user alice

- !grant
  role: !group ops
  member: !group development

- !grant
  role: !group everyone
  member: !group development
  member: !group operations
{% endhighlight %}

{% include toc.md key='statement-reference' section='permit' %}

Give privileges on a resource to a role.

Once a privilege is given, permission checks performed by the role will return `true`.

Note that permissions are not "inherited" by resource ids. For example, if a role has `read` privilege on a variable called `db`, that role does not automatically get `read` privilege on `variable:db/password`. In RBAC, inheritance of privileges only happens through role grants. RBAC is explicit in this way to avoid unintendend side-effects from the way that resources are named.

The `resource` must be defined in the same policy as the `!permit`. The `role` can be defined in any policy.

#### Example

{% highlight yaml %}
- !layer prod/app
        
- !variable prod/database/password
        
- !permit
  role: !layer prod/app
  privileges: [ read, execute ]
  resource: !variable prod/database/password
{% endhighlight %}

{% include toc.md key='statement-reference' section='delete' %}

Explicitly deletes an object. This statement should only be used in `PATCH` mode. 

Note that if an object exists in the database when a policy `PUT` update is made which does not include that object, then the object is deleted.

This operation is a nop if the object does not exist.

#### Attributes

* **record** The object to be deleted.

#### Permission Required

`update` on the policy.

#### Example

Given the policy:

{% highlight yaml %}
- !group developers
{% endhighlight %}

The following policy update deletes the group:

{% highlight yaml %}
- !delete
  record: !group developers
{% endhighlight %}

{% include toc.md key='statement-reference' section='revoke' %}

Explicitly revokes a role grant. This statement should only be used in `PATCH` mode. 

Note that if a role grant exists in the database when a policy `PUT` update is made which does not include that role grant, then the grant is revoked.

This operation is a nop if the role grant does not exist.

#### Attributes

* **member** The role from which the `role` will be revoked.
* **role** The role which has been granted.

#### Permission Required

`update` on the policy.

#### Example

Given the policy:

{% highlight yaml %}
- !group developers
- !group employees
- !grant
  role: !group employees
  member: !group developers
{% endhighlight %}

The following policy update revokes the grant:

{% highlight yaml %}
- !revoke
  role: !group employees
  member: !group developers
{% endhighlight %}

{% include toc.md key='statement-reference' section='deny' %}

Explicitly revokes a permission grant. This statement should only be used in `PATCH` mode. 

Note that if a permission grant exists in the database when a policy `PUT` update is made which does not include that permission grant grant, then the grant is revoked.

This operation is a nop if the permission grant does not exist.

#### Attributes

* **resource** The resource on which the privilege is granted.
* **privilege** The privilege which will be revoked.
* **role** The role from which the `privilege` (or privileges) will be revoked.

#### Permission Required

`update` on the policy.

#### Example

Given the policy:

{% highlight yaml %}
  - !variable db/password
  - !host host-01
  - !permit
    resource: !variable db/password
    privileges: [ read, execute, update ]
    role: !host host-01
{% endhighlight %}

The following policy update revokes the `update` privilege:

{% highlight yaml %}
- !deny
  resource: !variable db/password
  privilege: update
  role: !host host-01
{% endhighlight %}

