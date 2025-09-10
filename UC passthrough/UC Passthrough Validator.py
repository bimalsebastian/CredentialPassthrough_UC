# Databricks notebook source
from uc_passthrough_library import create_uc_passthrough_interface
spark_passthrough = create_uc_passthrough_interface(spark)

# COMMAND ----------

# MAGIC %md
# MAGIC ### Read from users folder : Should Pass

# COMMAND ----------


df = spark_passthrough.read.format('csv').load('abfss://studies@stgucpassthrough.dfs.core.windows.net/bimal/day1.csv')
df.display()

# COMMAND ----------

# MAGIC %md
# MAGIC ### Write to UC table df.write : Should Pass

# COMMAND ----------

df.write.saveAsTable('ctlg_uc_passthrough.sch_uc_v2.written_table', mode='overwrite')

# COMMAND ----------

# MAGIC %md
# MAGIC ### Write to UC table passthrough.write : Should Pass

# COMMAND ----------

spark_passthrough.write(df).saveAsTable('ctlg_uc_passthrough.sch_uc_v2.written_table', mode='overwrite')

# COMMAND ----------

# MAGIC %md
# MAGIC ### Read from UC Table : Should Pass

# COMMAND ----------

df = spark_passthrough.read.table('ctlg_uc_passthrough.sch_uc_v2.written_table')
df.display()

# COMMAND ----------

# MAGIC %md
# MAGIC ### Write to non external location path using df.write : Should Fail

# COMMAND ----------

df.write.mode('overwrite').format('csv').save("abfss://studies@stgucpassthrough.dfs.core.windows.net/restricted/day1.csv")

# COMMAND ----------

# MAGIC %md
# MAGIC ### Write to non external location path using passthrough.write(df) : Should pass

# COMMAND ----------

spark_passthrough.write(df).format('csv').save('abfss://studies@stgucpassthrough.dfs.core.windows.net/bimal/part-00000.csv')

# COMMAND ----------

# MAGIC %md
# MAGIC ### Read from restricted path with format override : Should Fail

# COMMAND ----------


df = spark_passthrough.read.format('delta').load('abfss://studies@stgucpassthrough.dfs.core.windows.net/restricted/part-00000.csv')
df.display()

# COMMAND ----------

# MAGIC %md
# MAGIC ### Read from restricted path with correct format : Should Fail

# COMMAND ----------

df = spark_passthrough.read.format('csv').load('abfss://studies@stgucpassthrough.dfs.core.windows.net/restricted/part-00000.csv')
df.display()

# COMMAND ----------

# MAGIC %md
# MAGIC ### Write restricted path with correct format : Should Fail
# MAGIC

# COMMAND ----------

spark_passthrough.write(df).format('csv').save('abfss://studies@stgucpassthrough.dfs.core.windows.net/restricted/part-00000.csv')
 
