"""
Hardware identification functions for MyFS.
"""

import socket
import uuid

from myfs_utils import calculate_sha256

def get_hostname():
  """Gets the computer's hostname."""
  try:
    return socket.gethostname()
  except Exception as e:
    print(f"Warning: Could not get hostname: {e}")
    return "UnknownHost"

def get_hardware_identifiers_string():
  """
  Collects a string of hardware identifiers.
  Tries WMI on Windows, falls back to MAC address.
  """
  ids = []
  try:
    # Try using WMI for more stable IDs on Windows
    import wmi

    c = wmi.WMI()
    # Motherboard Serial Number
    try:
      mb_info = c.Win32_BaseBoard()
      if mb_info and mb_info[0].SerialNumber:
        ids.append(f"MB_SN:{mb_info[0].SerialNumber.strip()}")
    except Exception:
      pass # Ignore if not found

    # CPU ID
    try:
      cpu_info = c.Win32_Processor()
      if cpu_info and cpu_info[0].ProcessorId:
        ids.append(f"CPU_ID:{cpu_info[0].ProcessorId.strip()}")
    except Exception:
      pass # Ignore if not found

    # System UUID (often very stable)
    try:
      sys_product = c.Win32_ComputerSystemProduct()
      if sys_product and sys_product[0].UUID:
        ids.append(f"SYS_UUID:{sys_product[0].UUID.strip()}")
    except Exception:
      pass

  except ImportError:
    print(
      "Warning: WMI module not found. Falling back to MAC address for hardware ID."
    )
  except Exception as e:
    print(f"Warning: WMI query failed: {e}. Falling back.")

  # MAC address (fallback or additional identifier)
  try:
    mac = uuid.getnode()
    if mac != 0: # Basic check
      mac_address = ":".join(
        ("%012X" % mac)[i : i + 2] for i in range(0, 12, 2)
      )
      if mac_address != "00:00:00:00:00:00":
        ids.append(f"MAC:{mac_address}")
  except Exception as e:
    print(f"Warning: Could not get MAC address: {e}")

  if not ids:
    print(
      "Critical Warning: Could not retrieve any hardware identifiers. Using a random fallback."
    )
    ids.append(f"FALLBACK_RANDOM:{uuid.uuid4().hex}") # Not ideal for machine binding

  ids.sort() # Ensure consistent order
  return "|".join(ids)

def get_machine_id_hash():
  """Gets a hash of the machine ID string for unique identification."""
  machine_id_str = get_hardware_identifiers_string()
  return calculate_sha256(machine_id_str.encode('utf-8')), machine_id_str 