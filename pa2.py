#Nicholas Lahey
#Carleton ID: 101266327
#Algonquin ID: 041198291

"""Fleet Auditor
Reads a device inventory in xml and a audit policy in yaml, 
finding all devices that breaks policy before writing a .json report
Use: python pa2.py DEVICES.xml POLICY.yaml
"""

import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
import yaml


class AuditError(Exception):
	"""Raised if input is missing or broken"""

class Device:
	"Base network device class"

	def __init__(self, device_id, role, os_version):
		self.id = device_id
		self.role = role
		self.os_version = os_version
		self.owner = ""
		self.interface_status = [] #list of states ie ["up", "down", ..... ]

	def __str__(self):
		"""Returns short description of device, 
		i.e. sw-core-01 (switch, os 15)"""

		return f"{self.id} ({self.role}) os {self.os_version})"

	def interfaces_down(self):
		"""Returns how many interfaces are down on a device"""

		return self.interface_status.count("down")

def parse_device(elem):
	"""Converts a device xml element into a device object, or 
	none if no id is present"""

	if "id" not in elem.attrib:
		return None 

	device = Device(elem.get("id"), elem.get("role", ""), elem.get("os", ""))
	owner = elem.find("owner")
	if owner is not None and owner.text is not None:
		device.owner = owner.text.strip()

	for interface in elem.findall("interface"):
		device.interface_status.append(interface.get("status", ""))
	return device
		
def load_inventory(path):
	"""Reads the given inventory xml and returns site, devices, 
	and skipped devices or raises AuditError if file is missing or invalid xml"""

	try: 
		root = ET.parse(path).getroot()
	except FileNotFoundError:
		raise AuditError(f"{path}: file not found")
	except ET.ParseError as err:
		raise AuditError(f"{path}: not valid XML ({err})")

	devices = []
	skipped = 0

	for elem in root.findall("device"):
		device = parse_device(elem)
		if device is None:
			skipped = skipped + 1 #skip devices without ID
		else:
			devices.append(device)
	return root.get("site"), devices, skipped

def load_policy(path): 
	"""Read the policy yaml, return as dict
	Raises AuditError when file is missing or invalid"""

	try: 
		data = yaml.safe_load(Path(path).read_text(encoding = "utf-8"))
	except FileNotFoundError:
		raise AuditError(f"{path}: file not found")
	except yaml.YAMLError as err:
		raise AuditError(f"{path}: not valid YAML ({err})")
	if data is None:
		return {}
	if not isinstance(data, dict):
		raise AuditError(f"{path}: policy must be a mapping")
	
	return data

def build_report(site, devices, skipped, policy):
	"""Build the audit report dictionary from the devices and policy files"""

	roles = {}
	interfaces = {"up": 0, "down": 0, "other": 0}
	for device in devices:
		roles[device.role] = roles.get(device.role, 0) + 1
		for status in device.interface_status:
			if status == "up":
				interfaces["up"] = interfaces["up"] + 1
			elif status == "down":
				interfaces["down"] = interfaces["down"] + 1
			else:
				interfaces["other"] = interfaces["other"] + 1

	return {
	"site": site, 
	"total_devices": len(devices),
	"skipped_devices": skipped,
	"roles": roles,
	"interfaces": interfaces,
	"violations": [], #DO LATER !!!!!!!!!!!!!!!!!
	"compliant": sorted(d.id for d in devices),
	}


def print_summary(report):
	"""Prints a short summary of the audit"""

	print(f"Site: {report['site']} - {report['total_devices']} devices "
		f"({report['skipped_devices']} skipped), "
		f"{len(report['violations'])} violations")

def main(argv):
	"""Runs the audit, returns exit code"""
	if len(argv) != 3:
		print("Usage: python pa2.py, DEVICES.xml, POLICY.yaml")
		return 2
	try: 
		site, devices, skipped = load_inventory(argv[1])
		policy = load_policy(argv[2])
	except AuditError as err:
		print(f"error: {err}")
		return 1

	report = build_report(site, devices, skipped, policy)
	Path("audit.json").write_text(json.dumps(report, indent = 2) + "\n", encoding = "utf-8")
	print_summary(report)
	return 0

if __name__ == "__main__":
	sys.exit(main(sys.argv))