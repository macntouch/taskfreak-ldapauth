---[find]---
			<?php
				if ($objEditItem->isLoaded()) {
			?>
---[replace]---
			<?php
				if (TZN_USER_PASS_MODE != 5) {
				if ($objEditItem->isLoaded()) {
			?>
---[find]---
			<tr>
				<th><span class="compulsory"><?php echo $langUser['password_confirm']; ?></span>:</th>
				<td><input type="password" name="password2" /></td>
			</tr>
---[replace]---
			<tr>
				<th><span class="compulsory"><?php echo $langUser['password_confirm']; ?></span>:</th>
				<td><input type="password" name="password2" /></td>
			</tr>
			<?php } ?>
