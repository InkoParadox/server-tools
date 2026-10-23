import types
from test_chrony import load_engine,SCRIPT
def new_engine():
    _,engine,_=load_engine();code=engine.split(b"<<'MIST_PYTHON'\n",1)[1].rsplit(b'\nMIST_PYTHON',1)[0]
    module=types.ModuleType('embedded_engine');exec(compile(code,str(SCRIPT),'exec'),module.__dict__);return module
