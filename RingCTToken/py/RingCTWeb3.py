import web3
web3 = web3.Web3(web3.HTTPProvider('http://127.0.0.1:8545'))
RingCTTokenContract = web3.eth.contract('0x1785af032781FC80cEc292B68AB45328F98ab528')
