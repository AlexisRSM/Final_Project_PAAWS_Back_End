"""Changed varchar 255 to 1300 animal.description

Revision ID: 35167411e166
Revises: 18d1fb55496c
Create Date: 2024-08-31 12:42:18.667476

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '35167411e166'
down_revision = '18d1fb55496c'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('animal', schema=None) as batch_op:
        batch_op.alter_column('description',
               existing_type=sa.VARCHAR(length=255),
               type_=sa.String(length=1300),
               existing_nullable=False)

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('animal', schema=None) as batch_op:
        batch_op.alter_column('description',
               existing_type=sa.String(length=1300),
               type_=sa.VARCHAR(length=255),
               existing_nullable=False)

    # ### end Alembic commands ###