.. -*- rst -*-

============
API versions
============

Concepts
========

In order to bring new features to users over time, the Ironic API
supports versioning. There are two kinds of versions in Ironic.

- ''major versions'', which have dedicated urls.
- ''microversions'', which can be requested through the use of the
  ``X-OpenStack-Ironic-API-Version`` header.

Beginning with the Kilo release, all API requests support the
``X-OpenStack-Ironic-API-Version`` header. This header SHOULD be supplied
with every request; in the absence of this header, each request is treated
as though coming from an older pre-Kilo client. This was done to preserve
backwards compatibility as we introduced new features in the server.

List API versions
=================

.. rest_method::  GET /

This fetches all the information about all known major API versions in the
deployment. Links to more specific information will be provided for each major
API version, as well as information about supported min and max microversions.

Normal response codes: 200

Request
-------

Response Example
----------------

.. rest_parameters::  parameters.yaml

    - description: description
    - versions: versions
    - version: version
    - id: id
    - links: links
    - min_version: x-openstack-ironic-api-min-version

.. literalinclude:: samples/api-root-response.json
   :language: javascript


Show v1 API
===========

.. rest_method::  GET /v1/

Show all the resources within the Ironic v1 API.

Normal response codes: 200

Request
-------

Response Example
----------------

.. rest_parameters::  parameters.yaml

    - id: id
    - links: links
    - openstack-request-id: openstack-request-id
    - x-openstack-ironic-api-version: header_version
    - x-openstack-ironic-api-min-version: x-openstack-ironic-api-min-version
    - x-openstack-ironic-api-max-version: x-openstack-ironic-api-max-version

.. literalinclude:: samples/api-v1-root-response.json
   :language: javascript