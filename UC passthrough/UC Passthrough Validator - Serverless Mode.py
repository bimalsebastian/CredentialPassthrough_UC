# Databricks notebook source
import os

os.environ['PASSTHROUGH_CLIENT_SECRET'] = dbutils.secrets.get(scope = "scpassthroughbimal", key = "passthrough-client-secret")

os.environ['PASSTHROUGH_CLIENT_ID'] = dbutils.secrets.get(scope = "scpassthroughbimal", key = "passthrough-client-id")
os.environ['PASSTHROUGH_TENANT_ID'] = dbutils.secrets.get(scope = "scpassthroughbimal", key = "passthrough-tenant-id") 
# dbutils.secrets.get(scope = "scpassthroughbimal", key = "passthrough-tenant-id")
os.environ['PASSTHROUGH_CACHE_TOKENS'] = 'True'
os.environ['PASSTHROUGH_STORAGE_URL'] = dbutils.secrets.get(scope = "scpassthroughbimal", key = "passthrough-storage-url")

os.environ['PASSTHROUGH_USE_CLIENT_CREDENTIALS'] = 'False'
os.environ['PASSTHROUGH_USE_INTERACTIVE_FLOW'] = 'True'

os.environ['PASSTHROUGH_CUSTOM_ADLS_FORMATS'] = "log, raw,csv, mriimage, pdf"
os.environ['PASSTHROUGH_FORCE_ADLS_PATTERNS'] = '/unified/'
os.environ['PASSTHROUGH_FORCE_UC_PATTERNS'] = '/unknow/'
os.environ['PASSTHROUGH_CUSTOM_UC_FORMATS'] = 'iceberg, delta, parquet'

# COMMAND ----------


from uc_passthrough_library import UCPassthroughDataFrameReader
spark_passthrough = UCPassthroughDataFrameReader(spark)

# COMMAND ----------


df = spark_passthrough.read.format('csv').load('abfss://studies@strucpassthrough.dfs.core.windows.net/bimal/day2_mod_2.csv')
df.display()

# COMMAND ----------


df = spark_passthrough.read.format('csv').load('abfss://studies@strucpassthrough.dfs.core.windows.net/secret/day1.csv')
df.display()

# COMMAND ----------

# MAGIC %md
# MAGIC Below is a table read. It uses the same object : spark_passthrough, but accesses through UC

# COMMAND ----------


df = spark_passthrough.read.format('delta').load('abfss://studies@strucpassthrough.dfs.core.windows.net/data/unified/producta/test_schema/test_table')
df.display()

# COMMAND ----------

df = spark_passthrough.read.table().load(`ctlg_uc_passthrough`.`test_schema`.`test_table`)
df.display()