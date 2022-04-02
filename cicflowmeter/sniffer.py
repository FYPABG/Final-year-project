import argparse

from scapy.sendrecv import AsyncSniffer
from flow_session import generate_session_class


def create_sniffer(
 input_file, input_interface, output_mode, output_file, url_model=None
):

    assert (input_file is None) ^ (input_interface is None)
    NewFlowSession = generate_session_class(output_mode, output_file, url_model)
    if input_file is not None:
        return AsyncSniffer(
            offline=input_file,
            filter="ip and (tcp or udp)",
            prn=None,
            session=NewFlowSession,
            store=False,
            timeout =30
        )
    else:
        return AsyncSniffer(
            iface=input_interface,
            filter="ip and (tcp or udp)",
            prn=None,
            session=NewFlowSession,
            store=False,
            timeout =30 
        )


def main(iteration):
    output_file="csvs/test-"+str(iteration)+".csv"
    sniffer = create_sniffer(
        None,
        "enp0s3",
        "flow",
        output_file,
    )
    sniffer.start()

    try:
        sniffer.join()
    except KeyboardInterrupt:
        sniffer.stop()
    finally:
        sniffer.join()

