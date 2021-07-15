"""Universal Binary Store functions.
"""

import os
import io
import json
import time
import logging
import requests

from datetime import datetime
from typing import Dict, List, Union

from cbapi.connection import BaseAPI
from cbapi.errors import ServerError, ClientError, ObjectNotFoundError

LOGGER = logging.getLogger("cbinterface.psc.ubs")


def request_file_downloads(cb: BaseAPI, sha256hashes: List, expiration_seconds: int = 900) -> Dict:
    """Request file download URLs.

    If the UBS has a file for the sha256, it should return a URL to GET the file content.

    Args:
        cb: Carbon Black Cloud API connection with correct permissions.
        sha256hashes: list of sha256 hashes
        expiration_seconds: How many seconds the file content should be accessible.

    Returns:
        A dict object describing results.
    """
    url = f"/ubs/v1/orgs/{cb.credentials.org_key}/file/_download"
    request_data = {"sha256": sha256hashes, "expiration_seconds": expiration_seconds}
    try:
        result = cb.post_object(url, request_data)
        return result.json()
    except ServerError as e:
        LOGGER.error(f"Caught ServerError: {e}")
        return False
    except ClientError as e:
        LOGGER.warning(f"got ClientError: {e}")
        return False
    except ValueError:
        LOGGER.warning(f"got unexpected {result}")
        return False


def get_file_content(cb: BaseAPI, file_found_object: Dict, compressed=True):
    """Return the file content as a byte string.

    Args:
        cb: Carbon Black Cloud API object
        file_found_object: Details about the files that were found to
          be available for download

    Returns:
        The raw or compressed file content bytes.
    """
    import io
    import zipfile

    sha256 = file_found_object["sha256"]
    url = file_found_object["url"]
    LOGGER.debug(f"getting file content for sha256={sha256} from: {url}")
    compressed_content = b""
    result = requests.get(url, stream=True, proxies=cb.session.proxies)
    if result.status_code == 200:
        for chunk in result.iter_content(io.DEFAULT_BUFFER_SIZE):
            compressed_content += chunk
    else:
        LOGGER.error(f"got {result.status_code} attempting file get: {result}")
        return False

    if compressed:
        return compressed_content

    with zipfile.ZipFile(io.BytesIO(compressed_content)) as zp:
        if "filedata" not in zp.namelist():
            LOGGER.error(f"unexpected UBS compressed file content: missing 'filedata'")
            return False
        with zp.open("filedata") as fp:
            return fp.read()


def get_file(cb: BaseAPI, file_found_object: Dict, write_path=None, compressed=True):
    """Get file and write content to disk.

    Args:
        cb: Carbon Black Cloud API object
        file_found_object: Details about the files that were found to
          be available for download
        write_path: Where to write the file. Default is sha256 or sha256.zip
        compressed: If true, write as zip file.

    Returns:
        The write_path if a file was written to disk.
    """
    sha256 = file_found_object["sha256"]
    if write_path is None:
        if compressed:
            write_path = f"{sha256}.zip"
        else:
            write_path = sha256
    LOGGER.debug(f"writing file with sha256={sha256} to: {write_path}")
    with open(write_path, "wb") as fp:
        fp.write(get_file_content(cb, file_found_object, compressed=compressed))

    if os.path.exists(write_path):
        LOGGER.info(f" + Wrote: {write_path}")
        return write_path
    return None


def request_and_get_file(
    cb: BaseAPI, sha256_hash, expiration_seconds: int = 900, write_path=None, compressed=True, return_bytes=False
):
    """Request and download any content for file with sha256 hash.

    Args:
        cb: Carbon Black Cloud API object
        sha256_hash: A sha256 hash to request.
        expiration_seconds: How many seconds the file content should be accessible.
        compressed: If true, return zip compressed bytes; else, return bytes.

    Returns:
        The file content as a byte string, or the file path the content was written to.
    """
    file_request_results = request_file_downloads(cb, [sha256_hash])
    for error in file_request_results["error"]:
        LOGGER.warning(f"UBS had an 'intermittent' error and you should re-try for sha256: {error}")
    for not_found in file_request_results["not_found"]:
        LOGGER.info(f"UBS did not find result for sha256: {not_found}")
    file_found_object = file_request_results["found"][0]
    if return_bytes:
        if write_path:
            LOGGER.warning(f"nonsensical for write_path and return_bytes to both be set.")
        return get_file_content(cb, file_found_object, compressed=compressed)
    return get_file(cb, file_found_object, write_path=write_path, compressed=compressed)


def request_and_get_files(cb: BaseAPI, sha256hashes: List, expiration_seconds: int = 900, compressed=True):
    """Request and download zip compressed files found by the sha256 list.

    Args:
        cb: Carbon Black Cloud API object
        sha256hashes: A list of sha256 hashes to request.
        expiration_seconds: How many seconds the file content should be accessible.
        compressed: If true, write as zip files.

    Returns:
        list of file paths that were written.
    """
    written_file_paths = []
    file_request_results = request_file_downloads(cb, sha256hashes)
    for error in file_request_results["error"]:
        LOGGER.warning(f"UBS had an 'intermittent' error and you should re-try for sha256: {error}")
    for not_found in file_request_results["not_found"]:
        LOGGER.info(f"UBS did not find result for sha256: {not_found}")
    for file_found_object in file_request_results["found"]:
        fpath = get_file(cb, file_found_object, compressed=compressed)
        written_file_paths.append(fpath)

    return written_file_paths


def yield_file_metadata(cb: BaseAPI, sha256hashes: List):
    """Yield metadata available for matching files."""
    url = f"/ubs/v1/orgs/{cb.credentials.org_key}/sha256"
    for sha256 in sha256hashes:
        try:
            yield cb.get_object(f"{url}/{sha256}/metadata")
        except ObjectNotFoundError as e:
            err_message = json.loads(e.message)
            LOGGER.info(f"UBS: {err_message['error_code']}: {err_message['message']}")
        except ServerError as e:
            LOGGER.error(f"Caught ServerError: {e}")
        except ClientError as e:
            LOGGER.warning(f"got ClientError: {e}")
            return False
        except Exception as e:
            LOGGER.error(f"UNHANDLED: {e}")


def get_file_metadata(cb: BaseAPI, sha256hashes: List):
    """Return any metadata available for any matching files."""
    return list(yield_file_metadata(cb, sha256hashes))


def yield_device_summary(cb: BaseAPI, sha256hashes: List):
    """Yield an overview of the devices that executed the file."""
    url = f"/ubs/v1/orgs/{cb.credentials.org_key}/sha256"
    for sha256 in sha256hashes:
        try:
            yield cb.get_object(f"{url}/{sha256}/summary/device")
        except ObjectNotFoundError as e:
            err_message = json.loads(e.message)
            LOGGER.info(f"UBS: {err_message['error_code']}: {err_message['message']}")
        except ServerError as e:
            LOGGER.error(f"Caught ServerError: {e}")
        except ClientError as e:
            LOGGER.warning(f"got ClientError: {e}")
            return False
        except Exception as e:
            LOGGER.error(f"UNHANDLED: {e}")


def get_device_summary(cb: BaseAPI, sha256hashes: List):
    """Return an overview of the devices that executed the file."""
    return list(yield_device_summary(cb, sha256hashes))


def yield_signature_summary(cb: BaseAPI, sha256hashes: List, rows: int = 5):
    """Yield an overview of digital signature for a given SHA-256 hash

    This API will return a summary of the observed digital signature results
    for a given SHA-256 hash. The digital signature information for a binary
    may vary from one machine to another based on a variety of factors,
    including the presence of an up-to-date signature catalog on the host,
    system clock variations, ability to reach OCSP servers, custom root trust
    anchors, and more. Therefore, the results are ordered by prevalence, such
    that the most observed signatures will be returned first. The number of
    results are configurable, up to a max of 100 entries. Digital signatures
    can be recorded in a separate file (known as a “catalog” file) or embedded
    inside of the binary itself (an “embedded” signature). This signature
    API will capture the results of the endpoint’s verification of the digital
    signature associated with a given SHA-256 hash, stating whether that signature
    validation was based on a catalog file or an embedded signature. It is not
    uncommon for a catalog signature to be frequently updated, such that this API
    can return a wide variety of sign_timestamp values for a given SHA-256 hash.
    """
    url = f"/ubs/v1/orgs/{cb.credentials.org_key}/sha256"
    for sha256 in sha256hashes:
        try:
            yield cb.get_object(f"{url}/{sha256}/summary/signature?rows={rows}")
        except ObjectNotFoundError as e:
            err_message = json.loads(e.message)
            LOGGER.info(f"UBS: {err_message['error_code']}: {err_message['message']}")
        except ServerError as e:
            LOGGER.error(f"Caught ServerError: {e}")
        except ClientError as e:
            LOGGER.warning(f"got ClientError: {e}")
            return False
        except Exception as e:
            LOGGER.error(f"UNHANDLED: {e}")


def get_signature_summary(cb: BaseAPI, sha256hashes: List):
    """Return an overview of digital signature for a given SHA-256 hash."""
    return list(yield_signature_summary(cb, sha256hashes))


def yield_file_path_summary(cb: BaseAPI, sha256hashes: List, rows: int = 5):
    """Summary of the observed file paths for given SHA-256 hashes.

    This API will return a summary of the observed file paths. The results are
    ordered by prevalence, such that the most observed file path will be returned
    first. The number of results are configurable, up to a max of 100 entries.
    """
    url = f"/ubs/v1/orgs/{cb.credentials.org_key}/sha256"
    for sha256 in sha256hashes:
        try:
            yield cb.get_object(f"{url}/{sha256}/summary/file_path?rows={rows}")
        except ObjectNotFoundError as e:
            err_message = json.loads(e.message)
            LOGGER.info(f"UBS: {err_message['error_code']}: {err_message['message']}")
        except ServerError as e:
            LOGGER.error(f"Caught ServerError: {e}")
        except ClientError as e:
            LOGGER.warning(f"got ClientError: {e}")
            return False
        except Exception as e:
            LOGGER.error(f"UNHANDLED: {e}")


def get_file_path_summary(cb: BaseAPI, sha256hashes: List):
    """Summary of the observed file paths for given SHA-256 hashes."""
    return list(yield_file_path_summary(cb, sha256hashes))


def consolidate_metadata_and_summaries(cb: BaseAPI, sha256hashes: List):
    """Combine file metadata and all summary information for given SHA-256 hashes.

    Args:
      cb: A Cb API object
      sha256hashes: list of hashes to query about.
    Returns:
      A list of dictionaries, where each dictionary is a combined result
      for the respective sha256 hash.
    """
    results = []
    for sha256 in sha256hashes:
        sha256_data = {
            "sha256": sha256,
            "metadata": [],
            "device_sumamry": [],
            "signature_summary": [],
            "file_path_summary": [],
        }
        sha256_data["metadata"] = get_file_metadata(cb, [sha256])
        if sha256_data["metadata"]:
            sha256_data["device_summary"] = get_device_summary(cb, [sha256])
            sha256_data["signature_summary"] = get_signature_summary(cb, [sha256])
            sha256_data["file_path_summary"] = get_file_path_summary(cb, [sha256])
        results.append(sha256_data)
    return results
