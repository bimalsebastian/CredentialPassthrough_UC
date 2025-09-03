# Databricks notebook source

from uc_passthrough_library import create_uc_passthrough_interface
spark_passthrough = create_uc_passthrough_interface(spark)

# COMMAND ----------


df = spark_passthrough.read.format('csv').load('abfss://studies@strucpassthrough.dfs.core.windows.net/bimal/day2_mod_2.csv')
df.display()

# COMMAND ----------

df.write.saveAsTable('ctlg_uc_passthrough.test_schema.written_table', mode='overwrite')

# COMMAND ----------

# MAGIC %md
# MAGIC Below is a table read. It uses the same object : spark_passthrough, but accesses through UC

# COMMAND ----------


df = spark_passthrough.read.format('delta').load('abfss://studies@strucpassthrough.dfs.core.windows.net/data/unified/producta/test_schema/test_table')
df.display()

# COMMAND ----------

df = spark_passthrough.read.table('ctlg_uc_passthrough.test_schema.test_table')
df.display()