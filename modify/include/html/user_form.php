---[find]---
	<fieldset>
		<legend><?php echo $langUser['account']; ?></legend>
		<p><?php echo $langUser['account_legend']; ?></p>
---[replace]---
    <?php if (TZN_USER_PASS_MODE != 5) { ?>
	<fieldset>
		<legend><?php echo $langUser['account']; ?></legend>
		<p><?php echo $langUser['account_legend']; ?></p>
---[find]---
		<?php
			}
		?>
	</fieldset>
---[replace]---
		<?php
			}
		?>
	</fieldset>
    <?php } ?>
