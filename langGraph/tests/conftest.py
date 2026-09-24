"""pytest 配置：把 langGraph 目录加入 sys.path，使 `import deepagent` 可用。

pytest 从 langGraph/tests/ 收集测试，本文件先加载，修正导入路径。
"""

import sys
from pathlib import Path

# langGraph 目录（本文件的父目录）
_LANGGRAPH_DIR = Path(__file__).resolve().parent.parent
if str(_LANGGRAPH_DIR) not in sys.path:
    sys.path.insert(0, str(_LANGGRAPH_DIR))
