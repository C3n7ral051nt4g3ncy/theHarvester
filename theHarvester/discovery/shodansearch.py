from theHarvester.discovery.constants import *
from theHarvester.lib.core import *
from shodan import exception
from shodan import Shodan
from collections import OrderedDict


class SearchShodan:

    def __init__(self):
        self.key = Core.shodan_key()
        if self.key is None:
            raise MissingKey('Shodan')
        self.api = Shodan(self.key)
        self.hostdatarow = []
        self.tracker: OrderedDict = OrderedDict()

    async def search_ip(self, ip):
        try:
            ipaddress = ip
            results = self.api.host(ipaddress)
            asn = ''
            domains = []
            hostnames = []
            ip_str = ''
            isp = ''
            org = ''
            ports = []
            title = ''
            server = ''
            product = ''
            technologies = []

            data_first_dict = dict(results['data'][0])

            if 'ip_str' in data_first_dict:
                ip_str += data_first_dict['ip_str']

            if 'http' in data_first_dict:
                http_results_dict = dict(data_first_dict['http'])
                if 'title' in http_results_dict:
                    title_val = str(http_results_dict['title']).strip()
                    if title_val != 'None':
                        title += title_val
                if 'components' in http_results_dict:
                    technologies.extend(iter(http_results_dict['components'].keys()))
                if 'server' in http_results_dict:
                    server_val = str(http_results_dict['server']).strip()
                    if server_val != 'None':
                        server += server_val

            for key, value in results.items():
                if key == 'asn':
                    asn += value
                elif key == 'domains':
                    value = sorted(value)
                    domains.extend(value)
                if key == 'hostnames':
                    value = [host.strip() for host in list(value)]
                    value.sort()
                    hostnames.extend(value)
                if key == 'isp':
                    isp += value
                elif key == 'org':
                    org += str(value)
                if key == 'ports':
                    value = sorted(value)
                    ports.extend(value)
                if key == 'product':
                    product += value

            technologies = list(set(technologies))

            self.tracker[ip] = {'asn': asn.strip(), 'domains': domains, 'hostnames': hostnames,
                                'ip_str': ip_str.strip(), 'isp': isp.strip(), 'org': org.strip(),
                                'ports': ports, 'product': product.strip(),
                                'server': server.strip(), 'technologies': technologies, 'title': title.strip()}

            return self.tracker
        except exception.APIError:
            print(f'{ip}: Not in Shodan')
            self.tracker[ip] = 'Not in Shodan'
        except Exception as e:
            # print(f'Error occurred in the Shodan IP search module: {e}')
            self.tracker[ip] = f'Error occurred in the Shodan IP search module: {e}'
        finally:
            return self.tracker
