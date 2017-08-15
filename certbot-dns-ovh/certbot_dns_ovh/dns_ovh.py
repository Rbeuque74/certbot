"""DNS Authenticator for OVH."""
import logging

import ovh
import ovh.exceptions

import zope.interface

from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common

logger = logging.getLogger(__name__)


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for OVH

    This Authenticator uses the OVH API to fulfill a dns-01 challenge.
    """

    description = ('Obtain certificates using a DNS TXT record (if you are using OVH for '
                   'DNS).')
    ttl = 120

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(add)
        add('credentials', help='OVH credentials INI file.')

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the OVH API.'

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            'credentials',
            'OVH credentials INI file',
            {
                'application_key': 'Application Key',
                'application_secret': 'Application Secret',
                'consumer_key': 'Consumer secret associated to your OVH account',
            }
        )

    def _perform(self, domain, validation_name, validation):
        self._get_ovh_client().add_txt_record(domain, validation_name, validation, self.ttl)

    def _cleanup(self, domain, validation_name, validation):
        self._get_ovh_client().del_txt_record(domain, validation_name, validation)

    def _get_ovh_client(self):
        return _OVHClient(self.credentials.conf('application_key'), self.credentials.conf('application_secret'), self.credentials.conf('consumer_key'))


class _OVHClient(object):
    """
    Encapsulates all communication with the OVH API.
    """

    def __init__(self, application_key, application_secret, consumer_key):
        self.client = ovh.Client(
            endpoint='ovh-eu', # For now, only EU region handles DNS
            application_key=application_key,
            application_secret=application_secret,
            consumer_key=consumer_key
        )

    def add_txt_record(self, domain, record_name, record_content, record_ttl):
        """
        Add a TXT record using the supplied information.

        :param str domain: The domain to use to look up the Cloudflare zone.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :param int record_ttl: The record TTL (number of seconds that the record may be cached).
        :raises certbot.errors.PluginError: if an error occurs communicating with the Cloudflare API
        """

        zone_name = self._find_zone_for_domain(domain)

        dns_record = self.client.post("/domain/zone/{0}/record".format(zone_name), fieldType='TXT',
                                 subDomain=record_name, target=record_content, ttl=record_ttl)
        record_id = dns_record['id']
        logger.debug("Added TXT record on OVH DNS Zone, ID is %d", record_id)

        self._refresh_dns_zone(zone_name)

    def _refresh_dns_zone(self, zone_name):
        self.client.post('/domain/zone/{0}/refresh'.format(zone_name))
        logger.info("Zone have been refreshed on OVH side")

        soa = self.client.get('/domain/zone/{0}/soa'.format(zone_name))
        logger.debug("SOA serial for DNS Zone is now %s", soa['serial'])

    def del_txt_record(self, domain, record_name, record_content):
        """
        Delete a TXT record using the supplied information.

        Note that both the record's name and content are used to ensure that similar records
        created concurrently (e.g., due to concurrent invocations of this plugin) are not deleted.

        Failures are logged, but not raised.

        :param str domain: The domain to use to look up the Cloudflare zone.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        """

        zone_name = self._find_zone_for_domain(domain)

        records = client.get("/domain/zone/{0}/record".format(zone_name), fieldType='TXT', subDomain=record_name)

        if len(records) <= 0:
            logger.debug("No record found, nothing to clean up")
            return
        record_id = records[0]

        if len(records) > 1:
            # Too many records, will delete the last one we added.
            record_id = records[-1]

        logger.debug("Deleting TXT record on DNS Zone (name=%s, id=%d)", record_name, record_id)

        client.delete('/domain/zone/{0}/record/{1}'.format(zone_name, record_id))

        self._refresh_dns_zone(zone_name)

    def _find_zone_for_domain(self, domain):
        """
        Find the zone_id for a given domain.

        :param str domain: The domain for which to find the zone_id.
        :returns: The zone_id, if found.
        :rtype: str
        :raises certbot.errors.PluginError: if no zone_id is found.
        """

        zone_name_guesses = dns_common.base_domain_name_guesses(domain)

        for zone_name in zone_name_guesses:
            try:
                self.client.get("/domain/zone/{0}".format(zone_name))
                logger.debug('Found zone %s against OVH API', zone_name)

                # TODO: check here if we are handling well zone declared on a sub-domain,
                # so that record_name correspond to the correct one.
                return zone_name
            except ovh.exceptions.ResourceNotFoundError as exception_catched:
                continue

        raise errors.PluginError('Unable to find DNS Zone for domain {0} in your OVH Account'
                                 .format(domain))
