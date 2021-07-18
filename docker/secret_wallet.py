#global variable
HOME_DIR="/usrhome"


import re
import sys
from secretwallet.main import main
if __name__ == '__main__':
    sys.argv[0] = re.sub(r'(-script\.pyw|\.exe)?$', '', sys.argv[0])
    sys.exit(main())
